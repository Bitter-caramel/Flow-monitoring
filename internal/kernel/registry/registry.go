// Package registry 是模块登记本（声明式，manifest 驱动）。
//
// 设计依据（文件结构文档 §6 + 架构 v0.3 第 4 章）：
//   - registry/backend-modules/*.json 是每个后端模块的"身份证"
//   - bootstrap 读这些文件才知道要启动哪些模块、按什么顺序、装哪个二进制
//   - 模块之间只声明依赖 ID，不感知具体实现（可替换）
//
// 与旧实现的区别：旧版靠 init() 自注册 + 全局单例，导致"启用模块要改内核
// import"。本版改为：manifest 文件是装配的唯一事实来源，bootstrap 只读目录。
package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"flow-monitoring/pkg/plugin"
)

// 错误哨兵值。
var (
	// ErrConflict 模块 ID 冲突。
	ErrConflict = errors.New("registry: module id conflict")

	// ErrUnresolvedDep 模块依赖了未注册的模块。
	ErrUnresolvedDep = errors.New("registry: unresolved dependency")

	// ErrCyclicDependency 检测到循环依赖。
	ErrCyclicDependency = errors.New("registry: cyclic dependency detected")
)

// Descriptor 模块声明（registry/backend-modules/*.json 文件的内容）。
//
//   - Binary：模块进程二进制名（相对插件目录），宿主据此启动进程
//   - Provides：本模块注册的服务名（DSH ctx.provide）
//   - Injects：本模块需要的服务名（DSH inject）；宿主据此展开隐含依赖参与拓扑排序
//   - HTTPBase：模块对外 HTTP 路由前缀（空 = 不提供 HTTP，如检测类后台模块）
//   - Enabled：是否参与装配。声明与开关放在同一处，加/减模块只动这一个文件；
//     缺省（不写该字段）视为启用，显式 false 才停用——避免忘了写字段导致全体不启动。
type Descriptor struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Layer    string   `json:"layer"` // "L0".."L3"
	Enabled  *bool    `json:"enabled,omitempty"`
	Depends  []string `json:"depends,omitempty"`
	Provides []string `json:"provides,omitempty"`
	Injects  []string `json:"injects,omitempty"`
	HTTPBase string   `json:"http_base,omitempty"`
	Binary   string   `json:"binary,omitempty"`
	// Core 表示"核心模块"：构建与清单层面不可裁剪、不可删除。
	// ★ 与 Enabled 是两件事：core 模块同样允许 enabled=false（这次不启动），
	//   自检只会提示"核心模块未启用"，不阻塞启动。
	Core bool `json:"core,omitempty"`
}

// IsEnabled 是否参与装配（缺省启用）。
func (d Descriptor) IsEnabled() bool { return d.Enabled == nil || *d.Enabled }

// LayerValue 把层名字符串转成 plugin.Layer（未知返回 LayerExtension 兜底）。
func (d Descriptor) LayerValue() plugin.Layer {
	switch d.Layer {
	case "L0":
		return plugin.LayerKernel
	case "L1":
		return plugin.LayerFoundation
	case "L2":
		return plugin.LayerFeature
	case "L3":
		return plugin.LayerExtension
	}
	return plugin.LayerExtension
}

// Registry 模块声明注册表（线程安全）。
type Registry struct {
	mu   sync.RWMutex
	mods map[string]Descriptor
}

// New 创建空注册表。
func New() *Registry {
	return &Registry{mods: make(map[string]Descriptor)}
}

// Load 从 dir 读取所有 *.json 模块声明文件。
//
// dir 不存在或为空时返回空注册表（宿主可回退到编译期内置清单）；
// 仅 JSON 解析失败或 ID 冲突时返回错误。
func Load(dir string) (*Registry, error) {
	r := New()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, fmt.Errorf("registry: read dir %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("registry: read %s: %w", e.Name(), err)
		}
		var d Descriptor
		if err := json.Unmarshal(b, &d); err != nil {
			return nil, fmt.Errorf("registry: parse %s: %w", e.Name(), err)
		}
		if err := r.Register(d); err != nil {
			return nil, fmt.Errorf("registry: %s: %w", e.Name(), err)
		}
	}
	return r, nil
}

// Register 注册一个模块声明。
func (r *Registry) Register(d Descriptor) error {
	if d.ID == "" {
		return fmt.Errorf("registry: empty id")
	}
	if d.Binary == "" {
		d.Binary = d.ID // 默认二进制名 = ID
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.mods[d.ID]; exists {
		return fmt.Errorf("%w: %s", ErrConflict, d.ID)
	}
	r.mods[d.ID] = d
	return nil
}

// Get 查询模块声明。
func (r *Registry) Get(id string) (Descriptor, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.mods[id]
	return d, ok
}

// Replace 覆盖（或新增）一个模块声明（用户扩展/覆盖内置用）。
func (r *Registry) Replace(d Descriptor) error {
	if d.ID == "" {
		return fmt.Errorf("registry: empty id")
	}
	if d.Binary == "" {
		d.Binary = d.ID
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mods[d.ID] = d
	return nil
}

// List 列出所有模块声明（按 ID 字典序稳定输出）。
func (r *Registry) List() []Descriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Descriptor, 0, len(r.mods))
	for _, d := range r.mods {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ListEnabled 列出参与装配的模块声明（按 ID 字典序稳定输出）。
//
// 与 List 的区别：List 返回全部声明（含 enabled=false 的，供展示/管理），
// 本方法只返回会被真正装配的。
func (r *Registry) ListEnabled() []Descriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Descriptor, 0, len(r.mods))
	for _, d := range r.mods {
		if d.IsEnabled() {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// TopologicalSort 返回装配顺序（依赖在前），只处理 enabled 的模块。
//
// DSH 式服务注入：先由全部启用模块的 Provides 建"服务名 → 提供者模块"映射，
// 再把每个模块的 Injects 展开成对提供者模块的隐含依赖，一并参与排序，
// 从而保证"提供者先启动、消费者后启动"。
//
// enabled=false 的模块既不参与排序，也不算"可被依赖"：若某个启用模块依赖了
// 一个已停用的模块，会在下面第 3 步报 ErrUnresolvedDep（提示去启用它），
// 而不是静默地少启动一个模块。
func (r *Registry) TopologicalSort() ([]Descriptor, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// 0. 过滤出启用模块（装配的唯一输入）
	active := make(map[string]Descriptor, len(r.mods))
	for id, d := range r.mods {
		if d.IsEnabled() {
			active[id] = d
		}
	}

	// 1. 服务名 → 提供者模块 ID
	provider := make(map[string]string)
	for _, d := range active {
		for _, svc := range d.Provides {
			if prev, dup := provider[svc]; dup && prev != d.ID {
				return nil, fmt.Errorf("%w: service %s provided by both %s and %s",
					ErrConflict, svc, prev, d.ID)
			}
			provider[svc] = d.ID
		}
	}

	// 2. 展开隐含依赖（Depends ∪ Injects→提供者）
	deps := make(map[string][]string, len(active))
	for id, d := range active {
		set := append([]string(nil), d.Depends...)
		for _, svc := range d.Injects {
			pid, ok := provider[svc]
			if !ok {
				return nil, fmt.Errorf("%w: %s injects service %s but no provider", ErrUnresolvedDep, id, svc)
			}
			if pid != id {
				set = append(set, pid)
			}
		}
		deps[id] = set
	}

	// 3. 校验依赖存在（未注册或已停用都算未解析）
	for id, ds := range deps {
		for _, dep := range ds {
			if _, ok := active[dep]; !ok {
				return nil, fmt.Errorf("%w: %s depends on %s (unregistered or disabled)", ErrUnresolvedDep, id, dep)
			}
		}
	}

	// 4. Kahn BFS（稳定输出）
	inDegree := make(map[string]int, len(active))
	dependents := make(map[string][]string)
	for id, ds := range deps {
		inDegree[id] = len(ds)
		for _, dep := range ds {
			dependents[dep] = append(dependents[dep], id)
		}
	}

	var queue []string
	for id, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, id)
		}
	}
	sort.Strings(queue)

	result := make([]Descriptor, 0, len(active))
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		result = append(result, active[cur])

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

	if len(result) != len(active) {
		var stuck []string
		for id, deg := range inDegree {
			if deg > 0 {
				stuck = append(stuck, id)
			}
		}
		sort.Strings(stuck)
		return result, fmt.Errorf("%w: stuck modules %v", ErrCyclicDependency, stuck)
	}
	return result, nil
}
