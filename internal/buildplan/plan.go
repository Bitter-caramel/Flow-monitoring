// Package buildplan 实现构建期裁剪的**纯逻辑**：清单驱动的模块选择 +
// 运行时依赖闭包 + 构建清单（build-manifest.json）。
//
// ★ 设计：bash / PowerShell 脚本只做薄壳，选择/闭包/构建清单的唯一实现都在
// 这里（由 cmd/fmbuild 调用），避免两平台各写一份逻辑而漂移，也绕开
// Windows PowerShell 5.1 读 UTF-8 文件必须显式 -Encoding UTF8 的陷阱。
//
// ★ 与 registry.TopologicalSort 的区别：拓扑排序只处理 enabled=true 的模块，
// 且"启用模块依赖未启用模块"会直接报错；构建期裁剪恰恰相反——闭包必须在
// **全部**清单上算（忽略 Enabled），否则 --modules=disposal 无法带出同样
// enabled=false 的 situation / detect。
package buildplan

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"flow-monitoring/internal/kernel/registry"
)

// Mode 构建模式。
type Mode string

const (
	// ModeAll 构建全部清单模块。
	ModeAll Mode = "all"
	// ModeCoreOnly 只构建 core==true 的模块。
	ModeCoreOnly Mode = "core-only"
	// ModeModules 只构建给定模块及其运行时依赖闭包。
	ModeModules Mode = "modules"
)

// ReasonNoSource 是 Skipped.Reason 的取值：清单里有该模块，但没有可构建的源码。
const ReasonNoSource = "no_source"

// ReasonMissingDepSource 是 Skipped.Reason 的取值：模块自身就算有源码，其运行时
// 依赖（闭包成员，不含自己）也被跳过，构建出来的进程运行期必然起不来，故一并跳过。
// 只用于 ModeAll / ModeCoreOnly；ModeModules 对缺源码直接报 ErrNoSource。
const ReasonMissingDepSource = "missing_dep_source"

// ReasonInProcess 是 Skipped.Reason 的取值：该模块是内嵌模块（以库形式链接进宿主），
// 不产出独立二进制，因此不参与构建选择。
const ReasonInProcess = "inprocess"

// ErrNoSource 表示 ModeModules 选中了没有源码、无法构建的模块。
var ErrNoSource = errors.New("buildplan: selected module has no source")

// ErrEmptyPlan 表示计划里既没有可构建、也没有被跳过的模块。
// 这通常意味着清单目录不存在或为空：registry.Load 对不存在的目录返回空表且
// err==nil，库层在此兜底，免得调用方把"空计划"当成"构建成功"的假报告。
var ErrEmptyPlan = errors.New("buildplan: empty plan (no modules matched)")

// Skipped 被跳过的模块。
type Skipped struct {
	ID     string `json:"id"`
	Binary string `json:"binary"`
	Reason string `json:"reason"`
}

// Plan 一次构建的选择结果。
//
// Warnings 是人类可读的提示（如"某模块因依赖被跳过而一并跳过"），由 CLI 打到
// stderr；库层只负责生成，不直接写任何输出，保持纯逻辑可测。
type Plan struct {
	Mode      Mode                  `json:"mode"`
	Requested []string              `json:"requested,omitempty"`
	Selected  []registry.Descriptor `json:"selected"`
	Skipped   []Skipped             `json:"skipped"`
	Warnings  []string              `json:"warnings,omitempty"`
}

// Build 根据清单与模式算出"这次会构建什么"。
//
// 闭包在**全部**清单上算（忽略 Enabled）：Depends ∪ (Injects → Provides 提供者)，
// 传递展开。因此 --modules=disposal 会带出 enabled=false 的 situation、detect。
//
// 源码缺失的处理：
//   - ModeModules ⇒ 闭包里任一成员缺源码就返回 ErrNoSource，消息列出所有缺源码的
//     模块 id 与期望路径；★ 此时仍返回非 nil 的 plan，便于 --list 如实展示
//     "会跳过什么"（构建路径只认 error，不会真的构建）。
//   - ModeAll / ModeCoreOnly ⇒ 缺源码的放进 Skipped（ReasonNoSource），不报错；
//     并做一次"依赖缺失传播"：只要某模块的运行时依赖（闭包成员，不含自己）被跳过，
//     该模块也跳过，reason=ReasonMissingDepSource，并在 Warnings 里记一条提示。
//     ★ 目的：绝不能构建一个运行期必然缺依赖起不来的模块还报成功。
//
// 两种模式对"缺源码"的语义**刻意不同**：ModeModules 是用户点了名要的，缺源码必须
// 报错；ModeAll/ModeCoreOnly 是"能构建多少算多少"，缺源码只跳过（真实仓库 13 个清单里，
// 除了 2 个内嵌模块 detect/rule，只有 importer/query 有源码，否则 --all 直接失败）。
//
// hasSource 为 nil 时视为"全部有源码"（不做源码裁剪）。
func Build(reg *registry.Registry, mode Mode, ids []string, hasSource func(registry.Descriptor) bool) (*Plan, error) {
	if reg == nil {
		return nil, errors.New("buildplan: nil registry")
	}
	if hasSource == nil {
		hasSource = func(registry.Descriptor) bool { return true }
	}

	provider, err := buildProviders(reg.List())
	if err != nil {
		return nil, err
	}

	roots, requested, err := selectRoots(reg, mode, ids)
	if err != nil {
		return nil, err
	}

	closure, err := expandClosure(reg, roots, provider)
	if err != nil {
		return nil, err
	}

	plan := &Plan{
		Mode:      mode,
		Requested: requested,
		Selected:  []registry.Descriptor{},
		Skipped:   []Skipped{},
	}

	if mode == ModeModules {
		for _, id := range closure {
			d, ok := reg.Get(id)
			if !ok {
				continue
			}
			// ★ 必须先判 InProcess：内嵌模块永远不产出二进制，绝不能走到拼
			// cmd/plugins/<binary>/main.go 的分支（binary 为空时会拼出 cmd/plugins//main.go）。
			if d.InProcess {
				plan.Skipped = append(plan.Skipped, Skipped{ID: d.ID, Binary: d.Binary, Reason: ReasonInProcess})
				continue
			}
			if hasSource(d) {
				plan.Selected = append(plan.Selected, d)
			} else {
				plan.Skipped = append(plan.Skipped, Skipped{ID: d.ID, Binary: d.Binary, Reason: ReasonNoSource})
			}
		}
	} else {
		plan.Selected, plan.Skipped, plan.Warnings = selectAllowingSkips(reg, closure, provider, hasSource)
	}

	sort.Slice(plan.Selected, func(i, j int) bool { return plan.Selected[i].ID < plan.Selected[j].ID })
	sort.Slice(plan.Skipped, func(i, j int) bool { return plan.Skipped[i].ID < plan.Skipped[j].ID })

	if len(plan.Selected) == 0 && len(plan.Skipped) == 0 {
		return plan, ErrEmptyPlan
	}
	if mode == ModeModules {
		// InProcess 是预期跳过，不是"选中了却缺源码"的错误；只有真正的缺源码才报错。
		var noSource []Skipped
		for _, s := range plan.Skipped {
			if s.Reason == ReasonNoSource {
				noSource = append(noSource, s)
			}
		}
		if len(noSource) > 0 {
			return plan, noSourceError(noSource)
		}
	}
	return plan, nil
}

// selectAllowingSkips 供 ModeAll / ModeCoreOnly 使用：缺源码的模块跳过，且把
// "依赖被跳过"的模块也一并跳过（传播到不动点）。返回 (selected, skipped, warnings)。
//
// 依赖缺失优先于自身缺源码：真实仓库里 modules.alert 自己也没源码，但它注入
// situation.level，而 situation 缺源码——正是这种"被依赖拖垮"的模块要显式记账，
// 否则 D2 在真实清单上完全触发不了。
func selectAllowingSkips(reg *registry.Registry, closure []string, provider map[string]string, hasSource func(registry.Descriptor) bool) ([]registry.Descriptor, []Skipped, []string) {
	// 每个闭包模块的运行时依赖（Depends ∪ Injects→提供者，排除自己）。
	deps := make(map[string][]string, len(closure))
	for _, id := range closure {
		if d, ok := reg.Get(id); ok {
			deps[id] = moduleDeps(d, provider)
		}
	}

	reason := make(map[string]string, len(closure))
	for _, id := range closure {
		d, ok := reg.Get(id)
		if !ok {
			continue
		}
		// ★ 先判 InProcess：内嵌模块永远不产出二进制，归入预期跳过，
		// 且不走到"检查源码是否存在"的分支。
		if d.InProcess {
			reason[id] = ReasonInProcess
			continue
		}
		if !hasSource(d) {
			reason[id] = ReasonNoSource
		}
	}

	// 依赖缺失传播：B 因缺源码被跳过 ⇒ 依赖 B 的 A 也跳过。重复到不动点，
	// 以便链式处理 A→B→C（C 缺源码 ⇒ B、A 依次被跳过）。
	// ★ InProcess 模块虽在 Skipped 里，但它是"以库形式链接进宿主"的，依赖它
	// 视为依赖已满足，不得因此把消费者判成 missing_dep_source。
	missDeps := make(map[string][]string)
	for changed := true; changed; {
		changed = false
		for _, id := range closure {
			if _, done := reason[id]; done {
				continue
			}
			var miss []string
			for _, dep := range deps[id] {
				if r, bad := reason[dep]; bad && r != ReasonInProcess {
					miss = append(miss, dep)
				}
			}
			if len(miss) > 0 {
				sort.Strings(miss)
				reason[id] = ReasonMissingDepSource
				missDeps[id] = miss
				changed = true
			}
		}
	}

	selected := []registry.Descriptor{}
	skipped := []Skipped{}
	var warnings []string
	for _, id := range closure {
		d, ok := reg.Get(id)
		if !ok {
			continue
		}
		r, bad := reason[id]
		if !bad {
			selected = append(selected, d)
			continue
		}
		skipped = append(skipped, Skipped{ID: d.ID, Binary: d.Binary, Reason: r})
		if r == ReasonMissingDepSource {
			warnings = append(warnings, fmt.Sprintf(
				"警告: 跳过 %s：其依赖 %s 不可用（无源码或依赖缺失）",
				d.ID, strings.Join(missDeps[id], ", ")))
		}
	}
	return selected, skipped, warnings
}

// moduleDeps 返回模块的运行时依赖（Depends ∪ Injects→提供者），排除自己，按 ID 排序。
// provider 已在 expandClosure 前校验过 Injects 均有提供者，这里查不到就跳过。
func moduleDeps(d registry.Descriptor, provider map[string]string) []string {
	seen := make(map[string]bool)
	var deps []string
	add := func(id string) {
		if id == "" || id == d.ID || seen[id] {
			return
		}
		seen[id] = true
		deps = append(deps, id)
	}
	for _, dep := range d.Depends {
		add(dep)
	}
	for _, svc := range d.Injects {
		if pid, ok := provider[svc]; ok {
			add(pid)
		}
	}
	sort.Strings(deps)
	return deps
}

// buildProviders 建立"服务名 → 提供者模块 ID"映射（在全部模块上算）。
// 同一服务被两个模块声明 ⇒ ErrConflict（与 TopologicalSort 同义，复用该错误）。
func buildProviders(all []registry.Descriptor) (map[string]string, error) {
	provider := make(map[string]string)
	for _, d := range all {
		for _, svc := range d.Provides {
			if prev, dup := provider[svc]; dup && prev != d.ID {
				return nil, fmt.Errorf("%w: service %s provided by both %s and %s",
					registry.ErrConflict, svc, prev, d.ID)
			}
			provider[svc] = d.ID
		}
	}
	return provider, nil
}

// selectRoots 按模式给出闭包起点。返回 (roots, requested, error)。
// requested 只在 ModeModules 下非空（用户显式点了名的模块，归一化后排序）。
func selectRoots(reg *registry.Registry, mode Mode, ids []string) ([]string, []string, error) {
	switch mode {
	case ModeAll:
		all := reg.List()
		roots := make([]string, 0, len(all))
		for _, d := range all {
			roots = append(roots, d.ID)
		}
		return roots, nil, nil
	case ModeCoreOnly:
		var roots []string
		for _, d := range reg.List() {
			if d.Core {
				roots = append(roots, d.ID)
			}
		}
		return roots, nil, nil
	case ModeModules:
		var roots, requested, missing []string
		seen := make(map[string]bool)
		for _, raw := range ids {
			id, ok := normalizeID(reg, raw)
			if !ok {
				missing = append(missing, raw)
				continue
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			roots = append(roots, id)
			requested = append(requested, id)
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			return nil, nil, fmt.Errorf("buildplan: unknown module id(s): %s", strings.Join(missing, ", "))
		}
		sort.Strings(requested)
		return roots, requested, nil
	default:
		return nil, nil, fmt.Errorf("buildplan: unknown mode %q", mode)
	}
}

// normalizeID 接受 "modules.query" 与 "query" 两种写法，返回清单里的规范 ID。
func normalizeID(reg *registry.Registry, id string) (string, bool) {
	if id == "" {
		return "", false
	}
	if _, ok := reg.Get(id); ok {
		return id, true
	}
	if !strings.HasPrefix(id, "modules.") {
		full := "modules." + id
		if _, ok := reg.Get(full); ok {
			return full, true
		}
	}
	return "", false
}

// expandClosure 在全部模块上做传递闭包（Depends ∪ Injects→提供者）。
// 依赖了未注册的模块、或 Injects 找不到提供者 ⇒ ErrUnresolvedDep 风格错误。
func expandClosure(reg *registry.Registry, roots []string, provider map[string]string) ([]string, error) {
	visited := make(map[string]bool, len(roots))
	queue := make([]string, 0, len(roots))
	for _, id := range roots {
		if !visited[id] {
			visited[id] = true
			queue = append(queue, id)
		}
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		d, ok := reg.Get(id)
		if !ok {
			return nil, fmt.Errorf("%w: %s is not registered", registry.ErrUnresolvedDep, id)
		}
		deps := append([]string(nil), d.Depends...)
		for _, svc := range d.Injects {
			pid, ok := provider[svc]
			if !ok {
				return nil, fmt.Errorf("%w: %s injects service %s but no provider",
					registry.ErrUnresolvedDep, d.ID, svc)
			}
			if pid != d.ID {
				deps = append(deps, pid)
			}
		}
		for _, dep := range deps {
			if _, ok := reg.Get(dep); !ok {
				return nil, fmt.Errorf("%w: %s depends on %s (unregistered)",
					registry.ErrUnresolvedDep, d.ID, dep)
			}
			if !visited[dep] {
				visited[dep] = true
				queue = append(queue, dep)
			}
		}
	}
	out := make([]string, 0, len(visited))
	for id := range visited {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// noSourceError 汇总缺源码的模块 id 与期望路径。
func noSourceError(skipped []Skipped) error {
	parts := make([]string, 0, len(skipped))
	for _, s := range skipped {
		parts = append(parts, fmt.Sprintf("%s (expected cmd/plugins/%s/main.go)", s.ID, s.Binary))
	}
	return fmt.Errorf("%w; selected modules without source: %s", ErrNoSource, strings.Join(parts, ", "))
}
