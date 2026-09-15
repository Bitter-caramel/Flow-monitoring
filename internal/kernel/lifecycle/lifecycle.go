package lifecycle

import (
	"context"
	"fmt"
	"sync"
	"time"

	"flow-monitoring/internal/kernel/plugin"
	"flow-monitoring/internal/kernel/registry"
)

// State 插件状态机。
//
//	Created → Mounting → Mounted → Starting → Started → Stopping → Stopped
//	任一阶段失败 → Error
type State int

const (
	StateCreated State = iota
	StateMounting
	StateMounted
	StateStarting
	StateStarted
	StateStopping
	StateStopped
	StateError
)

// String 状态名。
func (s State) String() string {
	switch s {
	case StateCreated:
		return "Created"
	case StateMounting:
		return "Mounting"
	case StateMounted:
		return "Mounted"
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

// Coordinator 批量装配协调器。
//
// 持有 registry（插件列表）+ plugin.Context（依赖注入容器）。
// StartAll 按拓扑序依次 Mount + Start；StopAll 逆序 Stop。
type Coordinator struct {
	reg *registry.Registry
	ctx *plugin.Context

	mu           sync.Mutex
	states       map[string]State
	errs         map[string]error
	startedOrder []string
}

// New 创建 Coordinator。
func New(reg *registry.Registry, ctx *plugin.Context) *Coordinator {
	return &Coordinator{
		reg:    reg,
		ctx:    ctx,
		states: make(map[string]State),
		errs:   make(map[string]error),
	}
}

// StartAll 按拓扑序装配所有插件（Mount → Start）。
//
// 任一插件失败：该插件置 Error，回滚已装配插件（逆序 Stop），返回包装错误。
func (c *Coordinator) StartAll(ctx context.Context) error {
	order, err := c.reg.TopologicalSort()
	if err != nil {
		return fmt.Errorf("lifecycle: topological sort: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var started []string
	for _, id := range order {
		select {
		case <-ctx.Done():
			c.rollbackLocked(started)
			return ctx.Err()
		default:
		}

		p, ok := c.reg.Get(id)
		if !ok {
			continue
		}

		// Mount 阶段：注册服务到 Context
		c.states[id] = StateMounting
		if err := p.Mount(c.ctx); err != nil {
			c.states[id] = StateError
			c.errs[id] = err
			c.rollbackLocked(started)
			return fmt.Errorf("lifecycle: mount %s: %w", id, err)
		}
		c.states[id] = StateMounted

		// Start 阶段：建立外部连接
		c.states[id] = StateStarting
		if err := p.Start(c.ctx); err != nil {
			c.states[id] = StateError
			c.errs[id] = err
			c.rollbackLocked(started)
			return fmt.Errorf("lifecycle: start %s: %w", id, err)
		}
		c.states[id] = StateStarted
		started = append(started, id)
	}

	c.startedOrder = started
	return nil
}

// StopAll 逆序停止所有已装配插件。
//
// 任一 Stop 失败记入 errs 但继续关闭其他插件；返回第一个错误。
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
		p, ok := c.reg.Get(id)
		if !ok {
			continue
		}
		c.states[id] = StateStopping
		if err := p.Stop(c.ctx); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("lifecycle: stop %s: %w", id, err)
			}
			c.errs[id] = err
		}
		c.states[id] = StateStopped
	}
	return firstErr
}

// State 查询插件状态（未装配返回 StateCreated）。
func (c *Coordinator) State(id string) State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.states[id]
}

// States 返回所有插件状态快照。
func (c *Coordinator) States() map[string]State {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]State, len(c.states))
	for k, v := range c.states {
		out[k] = v
	}
	return out
}

// Errs 返回各插件错误。
func (c *Coordinator) Errs() map[string]error {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]error, len(c.errs))
	for k, v := range c.errs {
		out[k] = v
	}
	return out
}

// StartedOrder 返回已装配插件顺序（拓扑序）。
func (c *Coordinator) StartedOrder() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.startedOrder))
	copy(out, c.startedOrder)
	return out
}

// rollbackLocked 逆序停止已装配插件（持锁调用，启动失败回滚用）。
func (c *Coordinator) rollbackLocked(started []string) {
	for i := len(started) - 1; i >= 0; i-- {
		id := started[i]
		p, ok := c.reg.Get(id)
		if !ok {
			continue
		}
		c.states[id] = StateStopping
		if err := p.Stop(c.ctx); err != nil {
			c.errs[id] = err
		}
		c.states[id] = StateStopped
	}
}

// WaitStarted 阻塞等待所有插件进入 Started（当前 StartAll 同步，仅做最终校验）。
func (c *Coordinator) WaitStarted(ctx context.Context, timeout time.Duration) error {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	<-ctx.Done()
	if err := ctx.Err(); err != nil && err != context.Canceled {
		return err
	}
	for id, s := range c.States() {
		if s != StateStarted && s != StateStopped {
			return fmt.Errorf("lifecycle: plugin %s in state %s", id, s)
		}
	}
	return nil
}
