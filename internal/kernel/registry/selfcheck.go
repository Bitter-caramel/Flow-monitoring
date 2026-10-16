package registry

import (
	"fmt"
	"sort"
)

// Issue 一条自检发现。
//
// Code 是稳定的机器可读标识（测试与前端都按它断言，不要用 Message 文本断言）。
type Issue struct {
	Code     string `json:"code"`
	ModuleID string `json:"module_id,omitempty"`
	Message  string `json:"message"` // 人读说明，含修复建议
}

// 自检发现的稳定标识。
const (
	CodeCoreMissing         = "core_missing"          // 清单里一个核心模块都没有
	CodeCoreDisabled        = "core_disabled"         // 核心模块未启用（Warning，不阻塞）
	CodeCoreDependsOptional = "core_depends_optional" // 核心模块依赖了非核心模块
	CodeTopologyError       = "topology_error"        // 拓扑排序失败（成环 / 缺能力提供者）
	CodeLayerMismatch       = "layer_mismatch"        // 层号与依赖方向不一致（Warning，不阻塞）
)

// SelfCheckReport 一次自检的结果。Errors 阻塞启动，Warnings 只提示。
type SelfCheckReport struct {
	OK       bool     `json:"ok"` // == len(Errors) == 0
	Errors   []Issue  `json:"errors,omitempty"`
	Warnings []Issue  `json:"warnings,omitempty"`
	Core     []string `json:"core"`    // 清单里的核心模块 id（有序）
	Enabled  []string `json:"enabled"` // 本次启用的模块 id（有序）
}

// SelfCheck 对当前注册表做一次自检（只读，不修改注册表）。
//
// 规则（按 ModuleID 排序后输出，结果稳定）：
//  1. 清单里没有任何 Core 模块            -> Error  core_missing
//  2. 某 Core 模块未启用                   -> Warning core_disabled（core 与 enabled 是两件事，不阻塞）
//  3. 某 Core 模块依赖了非 Core 模块       -> Error  core_depends_optional
//     （Depends 的模块 id ∪ Injects 展开得到的提供者模块）
//  4. TopologicalSort 返回错误             -> Error  topology_error（成环 / 缺能力提供者）
//  5. 某模块的 layer 低于它依赖模块的 layer -> Warning layer_mismatch
//
// 实现说明：
//   - 规则 3/5 的"服务名→提供者模块"映射与 TopologicalSort 同源（Provides 建映射、
//     Injects 展开为隐含依赖）；区别是这里对**全部已声明模块**求值（含 enabled=false），
//     这样即便是未启用的核心模块，其依赖也会被检查；缺提供者不在此报错，交由规则 4 兜底。
//   - 规则 5 的层高低直接用 Descriptor.LayerValue() 比较：以 pkg/plugin 的
//     Layer 常量定义为准 LayerKernel(L0)=0 < LayerFoundation(L1)=1 < LayerFeature(L2)=2
//     < LayerExtension(L3)=3；未知层经 LayerValue() 兜底为 LayerExtension(L3)。
//   - 本方法不持锁调用 TopologicalSort：sync.RWMutex 的读锁不可重入（有写者在等待时
//     递归 RLock 会死锁），故先 List() 取快照，再单独调用 TopologicalSort()。
func (r *Registry) SelfCheck() SelfCheckReport {
	mods := r.List() // 已按 ID 升序，且在 RLock 保护下取的快照

	byID := make(map[string]Descriptor, len(mods))
	coreIDs := make([]string, 0, len(mods))
	enabledIDs := make([]string, 0, len(mods))
	for _, d := range mods {
		byID[d.ID] = d
		if d.Core {
			coreIDs = append(coreIDs, d.ID)
		}
		if d.IsEnabled() {
			enabledIDs = append(enabledIDs, d.ID)
		}
	}

	var errs, warns []Issue

	// 规则 1：一个核心模块都没有。
	if len(coreIDs) == 0 {
		errs = append(errs, Issue{
			Code:    CodeCoreMissing,
			Message: `清单里没有任何 core 模块：请至少给一个关键模块加 "core": true（构建/清单层面不可裁剪）`,
		})
	}

	// 服务名 → 提供者模块（与 TopologicalSort 同源；对全部已声明模块求值）。
	// mods 已按 ID 升序，重复提供者这里取 ID 最小者，重复冲突交由规则 4 报错。
	provider := make(map[string]string)
	for _, d := range mods {
		for _, svc := range d.Provides {
			if _, exists := provider[svc]; !exists {
				provider[svc] = d.ID
			}
		}
	}

	// depsOf 展开某模块的依赖：Depends ∪ Injects→提供者（自依赖忽略）。
	depsOf := func(d Descriptor) []string {
		set := make([]string, 0, len(d.Depends)+len(d.Injects))
		set = append(set, d.Depends...)
		for _, svc := range d.Injects {
			if pid, ok := provider[svc]; ok && pid != d.ID {
				set = append(set, pid)
			}
		}
		return set
	}

	// 规则 2 & 3：核心模块未启用（Warning）；核心模块依赖非核心模块（Error）。
	for _, d := range mods {
		if !d.Core {
			continue
		}
		if !d.IsEnabled() {
			warns = append(warns, Issue{
				Code:     CodeCoreDisabled,
				ModuleID: d.ID,
				Message:  fmt.Sprintf("核心模块 %s 本次未启用（enabled=false）：core 只表示不可裁剪，这次不启动不阻塞", d.ID),
			})
		}
		for _, dep := range depsOf(d) {
			dd, ok := byID[dep]
			if !ok {
				continue // 依赖未注册：交由规则 4 拓扑错误兜底
			}
			if !dd.Core {
				errs = append(errs, Issue{
					Code:     CodeCoreDependsOptional,
					ModuleID: d.ID,
					Message:  fmt.Sprintf("核心模块 %s 依赖了非核心模块 %s：核心模块不得依赖可裁剪模块（把 %s 也标为 core，或去掉该依赖）", d.ID, dep, dep),
				})
			}
		}
	}

	// 规则 4：拓扑排序失败（成环 / 缺能力提供者）。
	if _, err := r.TopologicalSort(); err != nil {
		errs = append(errs, Issue{
			Code:    CodeTopologyError,
			Message: fmt.Sprintf("拓扑排序失败：%v", err),
		})
	}

	// 规则 5：消费者 layer 低于提供者/被依赖模块 layer（Warning）。
	for _, d := range mods {
		for _, dep := range depsOf(d) {
			dd, ok := byID[dep]
			if !ok {
				continue
			}
			if d.LayerValue() < dd.LayerValue() {
				warns = append(warns, Issue{
					Code:     CodeLayerMismatch,
					ModuleID: d.ID,
					Message:  fmt.Sprintf("模块 %s（%s）的层级低于其依赖 %s（%s）：建议把消费者放到更高层", d.ID, d.Layer, dep, dd.Layer),
				})
			}
		}
	}

	sortIssues(errs)
	sortIssues(warns)

	return SelfCheckReport{
		OK:       len(errs) == 0,
		Errors:   errs,
		Warnings: warns,
		Core:     coreIDs,
		Enabled:  enabledIDs,
	}
}

// sortIssues 按 (ModuleID, Code) 稳定排序，保证自检结果可复现。
func sortIssues(issues []Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].ModuleID != issues[j].ModuleID {
			return issues[i].ModuleID < issues[j].ModuleID
		}
		return issues[i].Code < issues[j].Code
	})
}
