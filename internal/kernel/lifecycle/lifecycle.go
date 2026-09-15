package lifecycle

import (
	"context"
	"fmt"
	"sync"
	"time"

	"flow-monitoring/internal/kernel/registry"
)

// State 单模块的状态机。
//
//	┌─────────┐ InitFn ┌──────────────┐ InitFn OK ┌──────────────┐
//	│ Created │ ────→  │ Initializing │ ────────→ │ Initialized  │
//	└─────────┘        └──────────────┘           └──────────────┘
//	                                                    │ StartFn
//	                                                    ↓
//	┌────────┐  StartFn OK  ┌──────────┐  StopFn  ┌──────────┐
//	│ Started│  ──────────→ │ Starting │  ←─────  │ Stopping │
//	└────────┘               └──────────┘          └──────────┘
//	     │                                              │
//	     └────────── StopFn ──────────────────────────→ ↓
//	                                              ┌────────┐
//	                                              │ Stopped│
//	                                              └────────┘
//
// 任一步出错：状态进入 StateError，错误记入 Coordinator.errs。
type State int

const (
	StateCreated State = iota
	StateInitializing
	StateInitialized
	StateStarting
	StateStarted
	StateStopping
	StateStopped
	StateError
)

// String 状态的人类可读名（日志/UI 用）。
func (s State) String() string {
	switch s {
	case StateCreated:
		return "Created"
	case StateInitializing:
		return "Initializing"
	case StateInitialized:
		return "Initialized"
	case StateStarting:
		return "Starting"
	case StateStarted:
		return "Started"
	case StateStopping:
		return "Stopping"
	case StateStopped:
		return "Stopped"
	case StateError:
		return "Error"
	}
	return "Unknown"
}

// Coordinator 批量启停协调器。
//
// 线程安全；状态查询与启停操作都加锁。
// 通常由 bootstrap 持有一个实例，运行期对外只暴露 States() 读取。
type Coordinator struct {
	reg *registry.Registry

	mu sync.Mutex

	states map[registry.ModuleID]State
	errs   map[registry.ModuleID]error

	// startedOrder 记录"启动成功"的模块顺序（按拓扑序），
	// StopAll 时按其逆序关闭。
	startedOrder []registry.ModuleID
}

// New 创建 Coordinator，绑定一个 registry 实例。
func New(reg *registry.Registry) *Coordinator {
	return &Coordinator{
		reg:    reg,
		states: make(map[registry.ModuleID]State),
		errs:   make(map[registry.ModuleID]error),
	}
}

// StartAll 按拓扑顺序启动所有已注册模块。
//
// 流程（每个模块）：
//  1. StateCreated → StateInitializing → 调 InitFn（若有）
//  2. StateInitializing → StateInitialized
//  3. StateInitialized → StateStarting → 调 StartFn（若有）
//  4. StateStarting → StateStarted，追加到 startedOrder
//
// 任一模块失败：
//   - 该模块状态置 StateError，错误记入 errs
//   - 调用 rollback 逆序关闭已启动的模块
//   - 返回带模块 ID 的包装错误
//
// ctx 取消：返回 ctx.Err() 并回滚已启动模块（注意：取消时正在执行的 Init/Start
// 仍会运行至完成，本协调器不能强行打断用户函数）。
func (c *Coordinator) StartAll(ctx context.Context) error {
	order, err := c.reg.TopologicalSort()
	if err != nil {
		return fmt.Errorf("lifecycle: topological sort: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var started []registry.ModuleID
	for _, id := range order {
		select {
		case <-ctx.Done():
			c.rollbackLocked(started)
			return ctx.Err()
		default:
		}

		m, ok := c.reg.Get(id)
		if !ok {
			// 不可能发生（拓扑序已校验），防御
			continue
		}

		// === Init 阶段 ===
		c.states[id] = StateInitializing
		if m.InitFn != nil {
			if err := m.InitFn(); err != nil {
				c.states[id] = StateError
				c.errs[id] = err
				c.rollbackLocked(started)
				return fmt.Errorf("lifecycle: init %s: %w", id, err)
			}
		}
		c.states[id] = StateInitialized

		// === Start 阶段 ===
		c.states[id] = StateStarting
		if m.StartFn != nil {
			if err := m.StartFn(); err != nil {
				c.states[id] = StateError
				c.errs[id] = err
				c.rollbackLocked(started)
				return fmt.Errorf("lifecycle: start %s: %w", id, err)
			}
		}
		c.states[id] = StateStarted
		started = append(started, id)
	}

	c.startedOrder = started
	return nil
}

// StopAll 按启动的逆序关闭所有已启动模块。
//
// 行为：
//   - 逐个调用 StopFn（若存在）；任一失败记入 errs 但继续关闭其他模块
//   - 调用 StopFn 前状态置 Stopping，调用后置 Stopped（无论成功失败）
//   - StopFn 应可幂等（重复调用不报错）
//   - 返回第一个遇到的关闭错误（如有）
//
// 未启动任何模块时直接返回 nil（不报错）。
func (c *Coordinator) StopAll(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var firstErr error
	for i := len(c.startedOrder) - 1; i >= 0; i-- {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		id := c.startedOrder[i]
		m, ok := c.reg.Get(id)
		if !ok || m == nil || m.StopFn == nil {
			continue
		}
		c.states[id] = StateStopping
		if err := m.StopFn(); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("lifecycle: stop %s: %w", id, err)
			}
			c.errs[id] = err
		}
		c.states[id] = StateStopped
	}
	return firstErr
}

// State 查询某模块当前状态。
//
// 未注册或未启动过的模块返回 StateCreated（零值）。
func (c *Coordinator) State(id registry.ModuleID) State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.states[id]
}

// States 返回所有模块状态的快照（启动期日志/UI 用）。
//
// 拷贝一份避免外部修改污染内部状态。
func (c *Coordinator) States() map[registry.ModuleID]State {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[registry.ModuleID]State, len(c.states))
	for k, v := range c.states {
		out[k] = v
	}
	return out
}

// Errs 返回每个模块的错误（启动/关闭失败时填充）。
func (c *Coordinator) Errs() map[registry.ModuleID]error {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[registry.ModuleID]error, len(c.errs))
	for k, v := range c.errs {
		out[k] = v
	}
	return out
}

// StartedOrder 返回成功启动的模块顺序（拓扑序）的拷贝。
// StopAll 会逆序使用此列表。
func (c *Coordinator) StartedOrder() []registry.ModuleID {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]registry.ModuleID, len(c.startedOrder))
	copy(out, c.startedOrder)
	return out
}

// rollbackLocked 逆序关闭已启动模块（持有锁的情况下调用）。
//
// 与 StopAll 区别：
//   - rollbackLocked 不返回错误（启动失败时已记入主错误）
//   - 仍记入 errs 便于事后排查
//   - 不更新 startedOrder（保持空，因启动失败）
func (c *Coordinator) rollbackLocked(started []registry.ModuleID) {
	for i := len(started) - 1; i >= 0; i-- {
		id := started[i]
		m, ok := c.reg.Get(id)
		if !ok || m == nil || m.StopFn == nil {
			continue
		}
		c.states[id] = StateStopping
		if err := m.StopFn(); err != nil {
			c.errs[id] = err
		}
		c.states[id] = StateStopped
	}
}

// WaitStarted 阻塞等待所有模块进入 Started 状态，或 ctx 超时/取消。
//
// 当前实现：StartAll 是同步的，所以本函数在 StartAll 返回后才被调用，
// 仅做最终状态校验。未来支持异步 StartAll 时改为真正的等待。
func (c *Coordinator) WaitStarted(ctx context.Context, timeout time.Duration) error {
	// 给定超时（即便 StartAll 是同步，调用方仍可设置 deadline 防御）
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	<-ctx.Done() // 同步 StartAll 下立即返回 nil 或 ctx.Err
	if err := ctx.Err(); err != nil && err != context.Canceled {
		return err
	}
	// 检查是否有模块未达 Started
	for id, s := range c.States() {
		if s != StateStarted && s != StateStopped {
			return fmt.Errorf("lifecycle: module %s in state %s, expected Started/Stopped", id, s)
		}
	}
	return nil
}
