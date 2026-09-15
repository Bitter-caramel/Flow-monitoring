package registry

import (
	"fmt"
	"sort"
	"sync"
)

// ModuleID 模块唯一标识。
//
// 命名约定："domain.subdomain"，例如 "kernel.transport" / "modules.parse" / "modules.situation"。
type ModuleID string

// Layer 模块所属层级（对应 v0.3 第 3 章）。
type Layer int

const (
	LayerKernel     Layer = iota // L0 内核
	LayerFoundation              // L1 基础功能
	LayerFeature                 // L2 具体功能
	LayerExtension               // L3 用户扩展
)

// String 输出层级简称（日志/UI 用）。
func (l Layer) String() string {
	switch l {
	case LayerKernel:
		return "L0"
	case LayerFoundation:
		return "L1"
	case LayerFeature:
		return "L2"
	case LayerExtension:
		return "L3"
	}
	return "L?"
}

// HealthStatus 模块健康状态。
//
// 由 ModuleInfo.HealthFn 返回，health 模块聚合所有模块状态做整体上报。
type HealthStatus struct {
	Healthy bool            `json:"healthy"`
	Message string          `json:"message,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// ModuleInfo 模块元信息。
//
// 生命周期函数（InitFn/StartFn/StopFn/HealthFn）允许为 nil——bootstrap 调用前
// 会先 nil-check，无对应函数的模块跳过该步骤。
//
// InitFn vs StartFn 的区别：
//   - InitFn：注册依赖、做自检（不与外部资源建立连接）
//   - StartFn：建立外部连接（DB、监听端口、启动 worker）
//
// StopFn 应可幂等调用（重复调用不报错）；启动失败时仍调用 StopFn 以清理部分资源。
type ModuleInfo struct {
	ID          ModuleID
	Name        string   // 人类可读名
	Description string
	Layer       Layer
	Depends     []ModuleID   // 依赖的其他模块 ID
	Provides    []string     // 提供的契约 ID（关联到 contract.Registry）

	// 生命周期函数（按 bootstrap 启动链路顺序）
	InitFn   func() error
	StartFn  func() error
	StopFn   func() error
	HealthFn func() HealthStatus
}

// Registry 模块注册表。
//
// 线程安全；bootstrap 启动期可 Register，启动后应只读（v3 流程"启动时只读"）。
// 运行期热加载需通过 Replace（仅测试/插件 host 用，生产路径不推荐）。
type Registry struct {
	mu      sync.RWMutex
	modules map[ModuleID]*ModuleInfo
}

// Default 包级默认注册表；业务模块在 init() 中向其 Register。
var Default = New()

// New 创建独立注册表（用于测试隔离）。
func New() *Registry {
	return &Registry{modules: make(map[ModuleID]*ModuleInfo)}
}

// Register 注册一个模块。
//
//   - m 或 m.ID 为空：返回 ErrInvalidModule
//   - ID 已存在：返回 ErrConflict
//   - 同一进程允许多个模块各自注册自己（典型 init() 模式）
func (r *Registry) Register(m *ModuleInfo) error {
	if m == nil || m.ID == "" {
		return ErrInvalidModule
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.modules[m.ID]; exists {
		return fmt.Errorf("%w: %s", ErrConflict, m.ID)
	}
	// 拷贝 Depends 切片避免外部修改污染注册表
	r.modules[m.ID] = m
	return nil
}

// MustRegister 注册；冲突时 panic（仅用于 init() 阶段，编程错误才 panic）。
func (r *Registry) MustRegister(m *ModuleInfo) {
	if err := r.Register(m); err != nil {
		panic(fmt.Errorf("registry: must register %s: %w", m.ID, err))
	}
}

// Get 查询模块。
func (r *Registry) Get(id ModuleID) (*ModuleInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.modules[id]
	return m, ok
}

// List 列出所有模块（按 ID 字典序稳定输出，便于日志展示）。
func (r *Registry) List() []*ModuleInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*ModuleInfo, 0, len(r.modules))
	for _, m := range r.modules {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// TopologicalSort 返回模块启动顺序（依赖在前）。
//
// 算法：Kahn BFS。
//   - 入度=0（无依赖）的模块先入队
//   - 出队一个模块后，把所有依赖它的模块入度 -1，归零的入队
//   - 若结果数 != 模块数，说明存在循环依赖
//
// 错误：
//   - ErrUnresolvedDep：模块依赖未注册的模块
//   - ErrCyclicDependency：循环依赖（同时返回参与环的模块 ID 列表）
func (r *Registry) TopologicalSort() ([]ModuleID, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// 1. 校验所有依赖都已注册
	for _, m := range r.modules {
		for _, dep := range m.Depends {
			if _, ok := r.modules[dep]; !ok {
				return nil, fmt.Errorf("%w: %s depends on unregistered %s",
					ErrUnresolvedDep, m.ID, dep)
			}
		}
	}

	// 2. 构建入度与反向索引
	inDegree := make(map[ModuleID]int, len(r.modules))
	rdependents := make(map[ModuleID][]ModuleID)
	for id, m := range r.modules {
		inDegree[id] = len(m.Depends)
		for _, dep := range m.Depends {
			rdependents[dep] = append(rdependents[dep], id)
		}
	}

	// 3. 入度=0 入队；按 ID 字典序保证稳定
	var queue []ModuleID
	for id, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, id)
		}
	}
	sort.Slice(queue, func(i, j int) bool { return queue[i] < queue[j] })

	result := make([]ModuleID, 0, len(r.modules))
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		result = append(result, cur)

		children := rdependents[cur]
		sort.Slice(children, func(i, j int) bool { return children[i] < children[j] })

		for _, child := range children {
			inDegree[child]--
			if inDegree[child] == 0 {
				queue = append(queue, child)
			}
		}
		sort.Slice(queue, func(i, j int) bool { return queue[i] < queue[j] })
	}

	if len(result) != len(r.modules) {
		// 有环：把仍残留入度>0 的模块列出（这些一定在环里或环下游）
		var stuck []ModuleID
		for id, deg := range inDegree {
			if deg > 0 {
				stuck = append(stuck, id)
			}
		}
		sort.Slice(stuck, func(i, j int) bool { return stuck[i] < stuck[j] })
		return result, fmt.Errorf("%w: stuck modules %v", ErrCyclicDependency, stuck)
	}
	return result, nil
}

// FindCycle 显式找一条循环依赖路径（用于启动日志）。
//
// 用 DFS 三色标记：
//   - white：未访问
//   - gray：在递归栈中
//   - black：访问完成
//
// 遇到 gray 节点即找到环；返回环上节点列表（首尾相同以便阅读）。
// 没有环返回 false。
func (r *Registry) FindCycle() ([]ModuleID, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	const (
		white = iota
		gray
		black
	)
	color := make(map[ModuleID]int, len(r.modules))
	var path, cycle []ModuleID
	var found bool

	var dfs func(id ModuleID)
	dfs = func(id ModuleID) {
		if found {
			return
		}
		color[id] = gray
		path = append(path, id)

		m := r.modules[id]
		// 依赖按字典序遍历保证可重现
		deps := append([]ModuleID(nil), m.Depends...)
		sort.Slice(deps, func(i, j int) bool { return deps[i] < deps[j] })
		for _, dep := range deps {
			switch color[dep] {
			case white:
				dfs(dep)
			case gray:
				// 找到环：截取 path 中从 dep 到当前
				for i, p := range path {
					if p == dep {
						cycle = append(cycle, path[i:]...)
						cycle = append(cycle, dep) // 闭合
						found = true
						return
					}
				}
			}
		}
		color[id] = black
		path = path[:len(path)-1]
	}

	ids := make([]ModuleID, 0, len(r.modules))
	for id := range r.modules {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		if color[id] == white {
			dfs(id)
		}
	}
	return cycle, found
}
