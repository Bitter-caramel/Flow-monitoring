package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// loadModules 把若干模块声明写成 t.TempDir() 下的 JSON 文件并 Load 回来。
// 用 map 构造 JSON，便于显式写 "enabled": false / "core": true 等字段。
func loadModules(t *testing.T, mods ...map[string]any) *Registry {
	t.Helper()
	dir := t.TempDir()
	for i, m := range mods {
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal module #%d: %v", i, err)
		}
		id, _ := m["id"].(string)
		fn := fmt.Sprintf("%02d_%s.json", i, strings.NewReplacer(".", "_", "/", "_").Replace(id))
		if err := os.WriteFile(filepath.Join(dir, fn), b, 0o644); err != nil {
			t.Fatalf("write %s: %v", fn, err)
		}
	}
	r, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(%s): %v", dir, err)
	}
	return r
}

// hasCode 判断 issues 里是否存在指定 Code（按 Code 断言，不按 Message 文本）。
func hasCode(issues []Issue, code string) bool {
	for _, is := range issues {
		if is.Code == code {
			return true
		}
	}
	return false
}

// findIssue 返回首个匹配 Code 的 Issue。
func findIssue(t *testing.T, issues []Issue, code string) Issue {
	t.Helper()
	for _, is := range issues {
		if is.Code == code {
			return is
		}
	}
	t.Fatalf("issue with code %q not found in %+v", code, issues)
	return Issue{}
}

// 测试 1：全绿 —— 一个 core + 两个非 core，依赖方向正确（消费者层 >= 提供者层）。
func TestSelfCheck_AllGreen(t *testing.T) {
	r := loadModules(t,
		map[string]any{"id": "mod.core", "name": "core", "version": "1", "layer": "L1", "core": true, "provides": []string{"svc.base"}},
		map[string]any{"id": "mod.b", "name": "b", "version": "1", "layer": "L2", "injects": []string{"svc.base"}},
		map[string]any{"id": "mod.c", "name": "c", "version": "1", "layer": "L3", "depends": []string{"mod.b"}},
	)

	rep := r.SelfCheck()
	if !rep.OK {
		t.Fatalf("OK = false, want true; errors=%+v warnings=%+v", rep.Errors, rep.Warnings)
	}
	if len(rep.Errors) != 0 {
		t.Fatalf("Errors = %+v, want none", rep.Errors)
	}
	if len(rep.Warnings) != 0 {
		t.Fatalf("Warnings = %+v, want none", rep.Warnings)
	}
	if want := []string{"mod.core"}; !reflect.DeepEqual(rep.Core, want) {
		t.Errorf("Core = %v, want %v", rep.Core, want)
	}
	if want := []string{"mod.b", "mod.c", "mod.core"}; !reflect.DeepEqual(rep.Enabled, want) {
		t.Errorf("Enabled = %v, want %v", rep.Enabled, want)
	}
}

// 测试 2：core_missing —— 一个 core 都没有 ⇒ Error，OK=false。
func TestSelfCheck_CoreMissing(t *testing.T) {
	r := loadModules(t,
		map[string]any{"id": "mod.a", "version": "1", "layer": "L1"},
		map[string]any{"id": "mod.b", "version": "1", "layer": "L2", "depends": []string{"mod.a"}},
	)

	rep := r.SelfCheck()
	if rep.OK {
		t.Fatalf("OK = true, want false (no core module)")
	}
	if !hasCode(rep.Errors, CodeCoreMissing) {
		t.Fatalf("Errors = %+v, want code %q", rep.Errors, CodeCoreMissing)
	}
	if is := findIssue(t, rep.Errors, CodeCoreMissing); is.ModuleID != "" {
		t.Errorf("core_missing ModuleID = %q, want empty", is.ModuleID)
	}
}

// 测试 3：core_disabled —— core 模块 enabled=false ⇒ Warning，且 OK 仍为 true（不阻塞）。
func TestSelfCheck_CoreDisabledIsOnlyWarning(t *testing.T) {
	r := loadModules(t,
		map[string]any{"id": "mod.core", "version": "1", "layer": "L1", "core": true, "enabled": false},
		map[string]any{"id": "mod.x", "version": "1", "layer": "L2"},
	)

	rep := r.SelfCheck()
	if !rep.OK {
		t.Fatalf("OK = false, want true (core disabled must not block); errors=%+v", rep.Errors)
	}
	if len(rep.Errors) != 0 {
		t.Fatalf("Errors = %+v, want none", rep.Errors)
	}
	if !hasCode(rep.Warnings, CodeCoreDisabled) {
		t.Fatalf("Warnings = %+v, want code %q", rep.Warnings, CodeCoreDisabled)
	}
	if is := findIssue(t, rep.Warnings, CodeCoreDisabled); is.ModuleID != "mod.core" {
		t.Errorf("core_disabled ModuleID = %q, want mod.core", is.ModuleID)
	}
}

// 测试 4a：core_depends_optional —— core 模块 depends 一个非 core 模块 ⇒ Error。
func TestSelfCheck_CoreDependsOptional_ByDepends(t *testing.T) {
	r := loadModules(t,
		map[string]any{"id": "mod.core", "version": "1", "layer": "L2", "core": true, "depends": []string{"mod.opt"}},
		map[string]any{"id": "mod.opt", "version": "1", "layer": "L1"},
	)

	rep := r.SelfCheck()
	if rep.OK {
		t.Fatalf("OK = true, want false")
	}
	if !hasCode(rep.Errors, CodeCoreDependsOptional) {
		t.Fatalf("Errors = %+v, want code %q", rep.Errors, CodeCoreDependsOptional)
	}
	if is := findIssue(t, rep.Errors, CodeCoreDependsOptional); is.ModuleID != "mod.core" {
		t.Errorf("core_depends_optional ModuleID = %q, want mod.core", is.ModuleID)
	}
}

// 测试 4b：core_depends_optional —— core 模块 injects 只有非 core 模块提供的能力 ⇒ Error。
func TestSelfCheck_CoreDependsOptional_ByInjects(t *testing.T) {
	r := loadModules(t,
		map[string]any{"id": "mod.core", "version": "1", "layer": "L2", "core": true, "injects": []string{"svc.onlyopt"}},
		map[string]any{"id": "mod.opt", "version": "1", "layer": "L1", "provides": []string{"svc.onlyopt"}},
	)

	rep := r.SelfCheck()
	if rep.OK {
		t.Fatalf("OK = true, want false")
	}
	if !hasCode(rep.Errors, CodeCoreDependsOptional) {
		t.Fatalf("Errors = %+v, want code %q", rep.Errors, CodeCoreDependsOptional)
	}
	if is := findIssue(t, rep.Errors, CodeCoreDependsOptional); is.ModuleID != "mod.core" {
		t.Errorf("core_depends_optional ModuleID = %q, want mod.core", is.ModuleID)
	}
}

// 测试 5a：topology_error —— A depends B、B depends A 成环 ⇒ Error。
func TestSelfCheck_TopologyError_Cycle(t *testing.T) {
	r := loadModules(t,
		map[string]any{"id": "mod.a", "version": "1", "layer": "L1", "core": true, "depends": []string{"mod.b"}},
		map[string]any{"id": "mod.b", "version": "1", "layer": "L1", "core": true, "depends": []string{"mod.a"}},
	)

	rep := r.SelfCheck()
	if rep.OK {
		t.Fatalf("OK = true, want false (cycle)")
	}
	if !hasCode(rep.Errors, CodeTopologyError) {
		t.Fatalf("Errors = %+v, want code %q", rep.Errors, CodeTopologyError)
	}
}

// 测试 5b：topology_error —— injects 一个没人提供的能力 ⇒ Error。
func TestSelfCheck_TopologyError_UnresolvedInject(t *testing.T) {
	r := loadModules(t,
		map[string]any{"id": "mod.a", "version": "1", "layer": "L1", "core": true, "injects": []string{"svc.nobody"}},
	)

	rep := r.SelfCheck()
	if rep.OK {
		t.Fatalf("OK = true, want false (unresolved inject)")
	}
	if !hasCode(rep.Errors, CodeTopologyError) {
		t.Fatalf("Errors = %+v, want code %q", rep.Errors, CodeTopologyError)
	}
}

// 测试 6：layer_mismatch —— 消费者 layer 低于提供者 ⇒ Warning，OK 仍为 true。
func TestSelfCheck_LayerMismatchIsWarning(t *testing.T) {
	r := loadModules(t,
		map[string]any{"id": "mod.core", "version": "1", "layer": "L2", "core": true, "provides": []string{"svc.p"}},
		map[string]any{"id": "mod.consumer", "version": "1", "layer": "L1", "injects": []string{"svc.p"}},
	)

	rep := r.SelfCheck()
	if !rep.OK {
		t.Fatalf("OK = false, want true (layer mismatch is a warning); errors=%+v", rep.Errors)
	}
	if len(rep.Errors) != 0 {
		t.Fatalf("Errors = %+v, want none", rep.Errors)
	}
	if !hasCode(rep.Warnings, CodeLayerMismatch) {
		t.Fatalf("Warnings = %+v, want code %q", rep.Warnings, CodeLayerMismatch)
	}
	if is := findIssue(t, rep.Warnings, CodeLayerMismatch); is.ModuleID != "mod.consumer" {
		t.Errorf("layer_mismatch ModuleID = %q, want mod.consumer", is.ModuleID)
	}
}

// 测试 7：Core 字段能从 JSON 正确读出。
func TestSelfCheck_CoreParsedFromJSON(t *testing.T) {
	r := loadModules(t,
		map[string]any{"id": "mod.core", "version": "1", "layer": "L1", "core": true, "provides": []string{"svc.base"}},
		map[string]any{"id": "mod.plain", "version": "1", "layer": "L2"},
	)

	d, ok := r.Get("mod.core")
	if !ok {
		t.Fatalf("Get(mod.core) not found")
	}
	if !d.Core {
		t.Errorf("Descriptor.Core = false, want true for mod.core")
	}
	p, ok := r.Get("mod.plain")
	if !ok {
		t.Fatalf("Get(mod.plain) not found")
	}
	if p.Core {
		t.Errorf("Descriptor.Core = true, want false for mod.plain (default)")
	}
}

// 附加：结果稳定有序（同 Code 多条时按 ModuleID 升序）。
func TestSelfCheck_IssuesSortedByModuleID(t *testing.T) {
	r := loadModules(t,
		map[string]any{"id": "mod.core", "version": "1", "layer": "L2", "core": true, "provides": []string{"svc.p"}},
		map[string]any{"id": "mod.z", "version": "1", "layer": "L1", "injects": []string{"svc.p"}},
		map[string]any{"id": "mod.a", "version": "1", "layer": "L1", "injects": []string{"svc.p"}},
	)

	rep := r.SelfCheck()
	var got []string
	for _, is := range rep.Warnings {
		if is.Code == CodeLayerMismatch {
			got = append(got, is.ModuleID)
		}
	}
	if want := []string{"mod.a", "mod.z"}; !reflect.DeepEqual(got, want) {
		t.Errorf("layer_mismatch ModuleIDs = %v, want %v (stable ascending)", got, want)
	}
}

// TestSelfCheck_RealManifests 拿仓库里**真实**的 registry/backend-modules 清单跑一次自检。
//
// ★ 这是"真实环境"守卫（踩坑 29 的教训：只用合成夹具等于没验）：
// 真实清单必须自检通过 —— 将来谁把 `core` 弄丢、或让核心模块依赖了可选模块，CI 会立刻红。
// 路径从本包（internal/kernel/registry）上溯三级到仓库根。
func TestSelfCheck_RealManifests(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "registry", "backend-modules")
	r, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(%s): %v", dir, err)
	}
	rep := r.SelfCheck()

	if !rep.OK {
		t.Fatalf("真实清单自检未通过，Errors=%+v", rep.Errors)
	}
	if len(rep.Core) == 0 {
		t.Fatal("真实清单里没有任何 core 模块（core_missing 应为 Error，这里应已被 OK=false 拦住）")
	}
	// ★ 核心模块本次未启用只允许是 Warning：modules.capture / modules.auth 当前就是 enabled=false，
	// 若哪天有人把它改成 Error，这条会立刻红（守住 12-1 修正过的语义）。
	for _, w := range rep.Warnings {
		if w.Code == CodeCoreDisabled && !strings.HasPrefix(w.ModuleID, "modules.") {
			t.Errorf("core_disabled 的 ModuleID 异常：%+v", w)
		}
	}
	t.Logf("真实清单自检通过：core=%v enabled=%d 个 warnings=%d 条", rep.Core, len(rep.Enabled), len(rep.Warnings))
}
