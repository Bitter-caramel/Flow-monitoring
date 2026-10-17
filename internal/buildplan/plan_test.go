package buildplan

import (
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"flow-monitoring/internal/kernel/registry"
)

// boolPtr 取局部变量地址，便于给 registry.Descriptor.Enabled 赋值。
func boolPtr(b bool) *bool { return &b }

// newReg 用合成描述符构造注册表（Register 对重复 ID 会报错，测试即失败）。
func newReg(t *testing.T, ds ...registry.Descriptor) *registry.Registry {
	t.Helper()
	r := registry.New()
	for _, d := range ds {
		if err := r.Register(d); err != nil {
			t.Fatalf("Register(%s): %v", d.ID, err)
		}
	}
	return r
}

// allSource 视所有模块都有源码（不做源码裁剪）。
func allSource(registry.Descriptor) bool { return true }

// idsOf 提取描述符 ID 切片（保持原顺序）。
func idsOf(ds []registry.Descriptor) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.ID)
	}
	return out
}

// skippedIDs 提取被跳过模块的 ID 切片（保持原顺序）。
func skippedIDs(ss []Skipped) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.ID)
	}
	return out
}

// skipReason 返回指定 ID 的跳过原因，找不到直接失败。
func skipReason(t *testing.T, ss []Skipped, id string) string {
	t.Helper()
	for _, s := range ss {
		if s.ID == id {
			return s.Reason
		}
	}
	t.Fatalf("skipped %q not found in %+v", id, ss)
	return ""
}

// containsID 判断 id 是否在切片中。
func containsID(ids []string, id string) bool {
	for _, s := range ids {
		if s == id {
			return true
		}
	}
	return false
}

// 测试 1：闭包必须在全部清单上算（忽略 Enabled），否则会静默丢掉 disabled 依赖。
func TestBuild_ClosureIgnoresEnabledTransitive(t *testing.T) {
	reg := newReg(t,
		registry.Descriptor{ID: "modules.A", Enabled: boolPtr(true), Injects: []string{"b.svc"}},
		registry.Descriptor{ID: "modules.B", Enabled: boolPtr(false), Provides: []string{"b.svc"}, Injects: []string{"c.svc"}},
		registry.Descriptor{ID: "modules.C", Enabled: boolPtr(false), Provides: []string{"c.svc"}},
	)

	plan, err := Build(reg, ModeModules, []string{"A"}, allSource)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	got := idsOf(plan.Selected)
	want := []string{"modules.A", "modules.B", "modules.C"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Selected ids = %v, want %v", got, want)
	}

	for _, id := range []string{"modules.B", "modules.C"} {
		d, ok := reg.Get(id)
		if !ok {
			t.Fatalf("module %s not registered", id)
		}
		if d.IsEnabled() {
			t.Errorf("%s IsEnabled() = true, want false（disabled 依赖必须仍被闭包带出）", id)
		}
	}
}

// 测试 2：缺源码在两种模式下的语义刻意不同。
func TestBuild_MissingSourceSemanticsByMode(t *testing.T) {
	reg := newReg(t,
		registry.Descriptor{ID: "modules.a", Depends: []string{"modules.b"}},
		registry.Descriptor{ID: "modules.b"},
	)
	has := func(d registry.Descriptor) bool { return d.ID == "modules.a" }

	// ModeModules：用户点名要 A，缺源码的 B 直接报 ErrNoSource，但仍返回非 nil plan。
	plan, err := Build(reg, ModeModules, []string{"a"}, has)
	if !errors.Is(err, ErrNoSource) {
		t.Fatalf("ModeModules err = %v, want ErrNoSource", err)
	}
	if plan == nil {
		t.Fatal("ModeModules plan = nil, want non-nil（--list 需如实展示会跳过什么）")
	}
	if containsID(idsOf(plan.Selected), "modules.b") {
		t.Errorf("Selected 含 modules.b，但它没有源码")
	}
	if got := skipReason(t, plan.Skipped, "modules.b"); got != ReasonNoSource {
		t.Errorf("modules.b reason = %q, want %q", got, ReasonNoSource)
	}

	// ModeAll：不报错，缺源码的 B 跳过；依赖 B 的 A 因依赖缺失一并跳过。
	planAll, err := Build(reg, ModeAll, nil, has)
	if err != nil {
		t.Fatalf("ModeAll err = %v, want nil", err)
	}
	if got := skipReason(t, planAll.Skipped, "modules.b"); got != ReasonNoSource {
		t.Errorf("ModeAll modules.b reason = %q, want %q", got, ReasonNoSource)
	}
	if got := skipReason(t, planAll.Skipped, "modules.a"); got != ReasonMissingDepSource {
		t.Errorf("ModeAll modules.a reason = %q, want %q", got, ReasonMissingDepSource)
	}
}

// 测试 3：服务提供冲突与未解析注入都必须显式报错，不能被静默掩盖。
func TestBuild_ProviderConflictAndUnresolvedInject(t *testing.T) {
	t.Run("provider-conflict", func(t *testing.T) {
		reg := newReg(t,
			registry.Descriptor{ID: "modules.a", Provides: []string{"x.svc"}},
			registry.Descriptor{ID: "modules.b", Provides: []string{"x.svc"}},
		)
		_, err := Build(reg, ModeAll, nil, allSource)
		if !errors.Is(err, registry.ErrConflict) {
			t.Fatalf("err = %v, want registry.ErrConflict", err)
		}
	})

	t.Run("unresolved-inject", func(t *testing.T) {
		reg := newReg(t,
			registry.Descriptor{ID: "modules.a", Injects: []string{"nobody.svc"}},
		)
		_, err := Build(reg, ModeAll, nil, allSource)
		if !errors.Is(err, registry.ErrUnresolvedDep) {
			t.Fatalf("err = %v, want registry.ErrUnresolvedDep", err)
		}
		msg := err.Error()
		if !strings.Contains(msg, "modules.a") || !strings.Contains(msg, "nobody.svc") {
			t.Errorf("err = %q, want 含模块 id %q 与服务名 %q", msg, "modules.a", "nobody.svc")
		}
	})
}

// 测试 4：空注册表 + 空选择 ⇒ ErrEmptyPlan，避免把"空计划"当成构建成功。
func TestBuild_EmptyPlanIsError(t *testing.T) {
	reg := registry.New()
	cases := []struct {
		name string
		mode Mode
	}{
		{"all", ModeAll},
		{"core-only", ModeCoreOnly},
		{"modules", ModeModules},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Build(reg, tc.mode, nil, allSource)
			if !errors.Is(err, ErrEmptyPlan) {
				t.Fatalf("Build(%s) err = %v, want ErrEmptyPlan", tc.mode, err)
			}
		})
	}
}

// 测试 5：ID 归一化（modules.query / query 等价）与 Selected/Skipped 稳定升序。
func TestBuild_IDNormalizationAndStableOrder(t *testing.T) {
	reg := newReg(t,
		registry.Descriptor{ID: "modules.query"},
		registry.Descriptor{ID: "modules.other"},
	)

	pFull, err := Build(reg, ModeModules, []string{"modules.query"}, allSource)
	if err != nil {
		t.Fatalf("Build(modules.query): %v", err)
	}
	pShort, err := Build(reg, ModeModules, []string{"query"}, allSource)
	if err != nil {
		t.Fatalf("Build(query): %v", err)
	}
	if want := []string{"modules.query"}; !reflect.DeepEqual(idsOf(pFull.Selected), want) {
		t.Fatalf("full id Selected = %v, want %v", idsOf(pFull.Selected), want)
	}
	if !reflect.DeepEqual(idsOf(pFull.Selected), idsOf(pShort.Selected)) {
		t.Errorf("modules.query 与 query 结果不同: %v vs %v", idsOf(pFull.Selected), idsOf(pShort.Selected))
	}

	// 多模块下 Selected/Skipped 均按 ID 升序，且多次调用结果一致。
	reg2 := newReg(t,
		registry.Descriptor{ID: "modules.c"},
		registry.Descriptor{ID: "modules.a"},
		registry.Descriptor{ID: "modules.b"},
	)
	has := func(d registry.Descriptor) bool { return d.ID != "modules.b" }

	var firstSel, firstSkip []string
	for i := 0; i < 5; i++ {
		p, err := Build(reg2, ModeAll, nil, has)
		if err != nil {
			t.Fatalf("Build 第 %d 次: %v", i, err)
		}
		sel, skip := idsOf(p.Selected), skippedIDs(p.Skipped)
		if !sort.StringsAreSorted(sel) {
			t.Fatalf("Selected 未升序: %v", sel)
		}
		if !sort.StringsAreSorted(skip) {
			t.Fatalf("Skipped 未升序: %v", skip)
		}
		if i == 0 {
			firstSel, firstSkip = sel, skip
			continue
		}
		if !reflect.DeepEqual(sel, firstSel) || !reflect.DeepEqual(skip, firstSkip) {
			t.Fatalf("第 %d 次结果漂移: sel=%v skip=%v, want sel=%v skip=%v", i, sel, skip, firstSel, firstSkip)
		}
	}
	if want := []string{"modules.a", "modules.c"}; !reflect.DeepEqual(firstSel, want) {
		t.Errorf("Selected = %v, want %v", firstSel, want)
	}
	if want := []string{"modules.b"}; !reflect.DeepEqual(firstSkip, want) {
		t.Errorf("Skipped = %v, want %v", firstSkip, want)
	}
}

// 测试 6：--core-only 只选 Core，--all 覆盖全部清单模块。
func TestBuild_CoreOnlyAndAll(t *testing.T) {
	reg := newReg(t,
		registry.Descriptor{ID: "modules.a", Core: true},
		registry.Descriptor{ID: "modules.b"},
		registry.Descriptor{ID: "modules.c", Core: true},
	)

	core, err := Build(reg, ModeCoreOnly, nil, allSource)
	if err != nil {
		t.Fatalf("ModeCoreOnly: %v", err)
	}
	if want := []string{"modules.a", "modules.c"}; !reflect.DeepEqual(idsOf(core.Selected), want) {
		t.Errorf("core-only Selected = %v, want %v", idsOf(core.Selected), want)
	}

	all, err := Build(reg, ModeAll, nil, allSource)
	if err != nil {
		t.Fatalf("ModeAll: %v", err)
	}
	if want := []string{"modules.a", "modules.b", "modules.c"}; !reflect.DeepEqual(idsOf(all.Selected), want) {
		t.Errorf("all Selected = %v, want %v", idsOf(all.Selected), want)
	}
	if len(all.Skipped) != 0 {
		t.Errorf("all Skipped = %+v, want none", all.Skipped)
	}
}

// 测试 7：真实清单里 detect/rule 是内嵌模块（inprocess），必须 skip:inprocess、不进 Selected。
func TestBuild_RealManifests_InProcessSkipped(t *testing.T) {
	reg, err := registry.Load("../../registry/backend-modules")
	if err != nil {
		t.Fatalf("registry.Load: %v", err)
	}
	has := func(d registry.Descriptor) bool {
		return d.ID == "modules.importer" || d.ID == "modules.query"
	}
	plan, err := Build(reg, ModeAll, nil, has)
	if err != nil {
		t.Fatalf("Build(ModeAll): %v", err)
	}
	for _, id := range []string{"modules.detect", "modules.rule"} {
		if containsID(idsOf(plan.Selected), id) {
			t.Errorf("%s 不应进 Selected（内嵌模块，不产出独立二进制）", id)
		}
		if got := skipReason(t, plan.Skipped, id); got != ReasonInProcess {
			t.Errorf("%s reason = %q, want %q", id, got, ReasonInProcess)
		}
	}
}

// 测试 8：依赖一个 InProcess 模块的模块不得被判 ReasonMissingDepSource（依赖视为已满足）。
// 用内存构造的清单，不依赖真实目录。
func TestBuild_DependencyOnInProcessIsSatisfied(t *testing.T) {
	reg := newReg(t,
		registry.Descriptor{ID: "modules.consumer", Injects: []string{"detect.feature"}},
		registry.Descriptor{ID: "modules.detect", InProcess: true, Provides: []string{"detect.feature"}},
	)
	has := func(d registry.Descriptor) bool { return d.ID == "modules.consumer" }

	plan, err := Build(reg, ModeAll, nil, has)
	if err != nil {
		t.Fatalf("Build(ModeAll): %v", err)
	}
	if got := skipReason(t, plan.Skipped, "modules.detect"); got != ReasonInProcess {
		t.Errorf("modules.detect reason = %q, want %q", got, ReasonInProcess)
	}
	if !containsID(idsOf(plan.Selected), "modules.consumer") {
		t.Errorf("依赖 InProcess 的 modules.consumer 应被选中, Selected=%v Skipped=%+v",
			idsOf(plan.Selected), plan.Skipped)
	}
	if containsID(skippedIDs(plan.Skipped), "modules.consumer") {
		t.Errorf("modules.consumer 不应被跳过（依赖 InProcess 视为已满足）: %+v", plan.Skipped)
	}

	// ModeModules 选中一个 InProcess 模块：应在"查源码"之前就判掉，skip:inprocess，
	// 且不得因"缺源码"报 ErrNoSource（这里 allSource 恒 true 仍应被跳过，证明判断在先）。
	pMod, err := Build(reg, ModeModules, []string{"detect"}, allSource)
	if err != nil {
		t.Fatalf("Build(ModeModules detect) err = %v, want nil", err)
	}
	if got := skipReason(t, pMod.Skipped, "modules.detect"); got != ReasonInProcess {
		t.Errorf("ModeModules modules.detect reason = %q, want %q", got, ReasonInProcess)
	}
	if containsID(idsOf(pMod.Selected), "modules.detect") {
		t.Errorf("ModeModules 下内嵌模块不应进 Selected: %v", idsOf(pMod.Selected))
	}
}
