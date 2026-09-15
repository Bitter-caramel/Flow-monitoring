package registry

import (
	"fmt"
	"sort"
	"sync"

	"flow-monitoring/internal/kernel/plugin"
)

// Registry 插件注册表。
//
// 管理 plugin.Plugin：注册 / 查询 / 拓扑排序 / 循环依赖检测。
// 插件在 init() 中通过 Default.Register 自注册；bootstrap 读注册表装配。
//
// 可替换性：Register 对同 ID 冲突报错；Replace 强制覆盖（同名替换）。
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]plugin.Plugin
}

// Default 包级默认注册表；插件在 init() 中向其自注册。
var Default = New()

// New 创建独立注册表（测试隔离用）。
func New() *Registry {
	return &Registry{plugins: make(map[string]plugin.Plugin)}
}

// Register 注册一个插件。
//
// 同 ID 已存在时返回 ErrConflict（保护内置插件不被误覆盖）。
func (r *Registry) Register(p plugin.Plugin) error {
	if p == nil || p.Manifest().ID == "" {
		return ErrInvalidPlugin
	}
	id := p.Manifest().ID
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.plugins[id]; exists {
		return fmt.Errorf("%w: %s", ErrConflict, id)
	}
	r.plugins[id] = p
	return nil
}

// MustRegister 注册；冲突 panic（仅 init() 阶段编程错误）。
func (r *Registry) MustRegister(p plugin.Plugin) {
	if err := r.Register(p); err != nil {
		panic(fmt.Errorf("registry: must register %s: %w", p.Manifest().ID, err))
	}
}

// Replace 强制覆盖已注册插件（可替换性）。
func (r *Registry) Replace(p plugin.Plugin) error {
	if p == nil || p.Manifest().ID == "" {
		return ErrInvalidPlugin
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.plugins[p.Manifest().ID] = p
	return nil
}

// Get 查询插件。
func (r *Registry) Get(id string) (plugin.Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.plugins[id]
	return p, ok
}

// List 列出所有插件（按 ID 字典序稳定输出）。
func (r *Registry) List() []plugin.Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]plugin.Plugin, 0, len(r.plugins))
	for _, p := range r.plugins {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Manifest().ID < out[j].Manifest().ID
	})
	return out
}

// TopologicalSort 返回插件装配顺序（依赖在前）。
//
// 依赖未注册返回 ErrUnresolvedDep；循环依赖返回 ErrCyclicDependency。
func (r *Registry) TopologicalSort() ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// 1. 校验依赖存在
	for id, p := range r.plugins {
		for _, dep := range p.Manifest().Depends {
			if _, ok := r.plugins[dep]; !ok {
				return nil, fmt.Errorf("%w: %s depends on unregistered %s", ErrUnresolvedDep, id, dep)
			}
		}
	}

	// 2. 入度 + 反向索引
	inDegree := make(map[string]int, len(r.plugins))
	dependents := make(map[string][]string)
	for id, p := range r.plugins {
		deps := p.Manifest().Depends
		inDegree[id] = len(deps)
		for _, dep := range deps {
			dependents[dep] = append(dependents[dep], id)
		}
	}

	// 3. Kahn BFS
	var queue []string
	for id, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, id)
		}
	}
	sort.Strings(queue)

	result := make([]string, 0, len(r.plugins))
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		result = append(result, cur)

		children := append([]string(nil), dependents[cur]...)
		sort.Strings(children)
		for _, child := range children {
			inDegree[child]--
			if inDegree[child] == 0 {
				queue = append(queue, child)
			}
		}
		sort.Strings(queue)
	}

	if len(result) != len(r.plugins) {
		var stuck []string
		for id, deg := range inDegree {
			if deg > 0 {
				stuck = append(stuck, id)
			}
		}
		sort.Strings(stuck)
		return result, fmt.Errorf("%w: stuck plugins %v", ErrCyclicDependency, stuck)
	}
	return result, nil
}

// FindCycle 显式找一条循环依赖路径（启动日志用）。
func (r *Registry) FindCycle() ([]string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	const (
		white = iota
		gray
		black
	)
	color := make(map[string]int, len(r.plugins))
	var path, cycle []string
	var found bool

	var dfs func(id string)
	dfs = func(id string) {
		if found {
			return
		}
		color[id] = gray
		path = append(path, id)

		p := r.plugins[id]
		deps := append([]string(nil), p.Manifest().Depends...)
		sort.Strings(deps)
		for _, dep := range deps {
			switch color[dep] {
			case white:
				dfs(dep)
			case gray:
				for i, n := range path {
					if n == dep {
						cycle = append(cycle, path[i:]...)
						cycle = append(cycle, dep)
						found = true
						return
					}
				}
			}
		}
		color[id] = black
		path = path[:len(path)-1]
	}

	ids := make([]string, 0, len(r.plugins))
	for id := range r.plugins {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if color[id] == white {
			dfs(id)
		}
	}
	return cycle, found
}
