package buildplan

import (
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"flow-monitoring/internal/kernel/registry"
)

// 测试 15：ModulePackage 按清单把 id 精确映射成包路径（13 个真实清单全覆盖，其中 2 个内嵌模块归 Warnings）。
func TestModulePackage_MapsManifests(t *testing.T) {
	reg, err := registry.Load("../../registry/backend-modules")
	if err != nil {
		t.Fatalf("registry.Load: %v", err)
	}
	all := reg.List()
	if len(all) != 13 {
		t.Fatalf("清单模块数 = %d, want 13", len(all))
	}
	for _, d := range all {
		short := strings.TrimPrefix(d.ID, "modules.")
		p, err := ModulePackage(d)
		if err != nil {
			t.Fatalf("ModulePackage(%s): %v", d.ID, err)
		}
		want := "flow-monitoring/internal/modules/" + short
		if p != want {
			t.Errorf("ModulePackage(%s) = %q, want %q", d.ID, p, want)
		}
	}

	// id 不以 modules. 开头 ⇒ 必须返回 error，不能瞎猜包路径。
	if _, err := ModulePackage(registry.Descriptor{ID: "alert"}); err == nil {
		t.Error("ModulePackage(alert) err = nil, want error")
	}
	if _, err := ModulePackage(registry.Descriptor{ID: "modules."}); err == nil {
		t.Error("ModulePackage(modules.) err = nil, want error")
	}
}

// 测试 16（★ 守卫的命门）：合成边表能抓出"宿主耦合可选模块"，并指出谁 import 了它。
// 这条证明守卫"能抓到"，而不是"今天恰好没违规所以绿"。
func TestGuardHostDeps_DetectsViolationAndNamesImporter(t *testing.T) {
	reg := newReg(t, registry.Descriptor{ID: "modules.alert"})
	const (
		server    = "flow-monitoring/cmd/server"
		bootstrap = "flow-monitoring/internal/kernel/bootstrap"
	)
	edges := map[string][]string{
		server:    {bootstrap},
		bootstrap: {"flow-monitoring/internal/modules/alert"},
	}

	report := GuardHostDeps(reg, edges)
	if report.Checked != 2 {
		t.Errorf("Checked = %d, want 2", report.Checked)
	}
	if len(report.Errors) != 1 {
		t.Fatalf("Errors = %+v, want 恰好 1 条", report.Errors)
	}
	got := report.Errors[0]
	if got.ModuleID != "modules.alert" {
		t.Errorf("ModuleID = %q, want modules.alert", got.ModuleID)
	}
	if got.Core {
		t.Error("Core = true, want false（可选模块）")
	}
	if got.Package != "flow-monitoring/internal/modules/alert" {
		t.Errorf("Package = %q, want flow-monitoring/internal/modules/alert", got.Package)
	}
	wantBy := []string{bootstrap}
	if !reflect.DeepEqual(got.ImportedBy, wantBy) {
		t.Errorf("ImportedBy = %v, want %v", got.ImportedBy, wantBy)
	}
	if len(report.Warnings) != 0 {
		t.Errorf("Warnings = %+v, want none", report.Warnings)
	}
}

// 测试 17：core 模块被 import 只进 Warnings，Errors 必须为空。
func TestGuardHostDeps_CoreIsWarningOnly(t *testing.T) {
	reg := newReg(t, registry.Descriptor{ID: "modules.query", Core: true})
	edges := map[string][]string{
		"flow-monitoring/internal/kernel/bootstrap": {"flow-monitoring/internal/modules/query"},
	}

	report := GuardHostDeps(reg, edges)
	if len(report.Errors) != 0 {
		t.Errorf("Errors = %+v, want none（core 模块只告警）", report.Errors)
	}
	if len(report.Warnings) != 1 {
		t.Fatalf("Warnings = %+v, want 1 条", report.Warnings)
	}
	got := report.Warnings[0]
	if got.ModuleID != "modules.query" || !got.Core {
		t.Errorf("Warnings[0] = %+v, want modules.query core=true", got)
	}
	if want := []string{"flow-monitoring/internal/kernel/bootstrap"}; !reflect.DeepEqual(got.ImportedBy, want) {
		t.Errorf("ImportedBy = %v, want %v", got.ImportedBy, want)
	}
}

// 测试 18：store 在宿主闭包里但没有清单 ⇒ 既不进 Errors 也不进 Warnings
// （防止"含 internal/modules/ 就算违规"的粗规则复活）。
func TestGuardHostDeps_StoreIsNotAModule(t *testing.T) {
	reg, err := registry.Load("../../registry/backend-modules")
	if err != nil {
		t.Fatalf("registry.Load: %v", err)
	}
	edges := map[string][]string{
		"flow-monitoring/internal/kernel/bootstrap": {"flow-monitoring/internal/modules/store"},
	}

	report := GuardHostDeps(reg, edges)
	if len(report.Errors) != 0 || len(report.Warnings) != 0 {
		t.Fatalf("Errors=%+v Warnings=%+v, want none（store 无清单，不是模块）", report.Errors, report.Warnings)
	}
	if report.Checked != 1 {
		t.Errorf("Checked = %d, want 1", report.Checked)
	}
}

// 测试 19：nil 与空边表 ⇒ Checked==0、无违规、无 panic。
func TestGuardHostDeps_EmptyEdges(t *testing.T) {
	reg := newReg(t, registry.Descriptor{ID: "modules.alert"})
	cases := []struct {
		name  string
		edges map[string][]string
	}{
		{"nil", nil},
		{"empty", map[string][]string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := GuardHostDeps(reg, tc.edges)
			if report.Checked != 0 {
				t.Errorf("Checked = %d, want 0", report.Checked)
			}
			if len(report.Errors) != 0 || len(report.Warnings) != 0 {
				t.Errorf("Errors=%+v Warnings=%+v, want none", report.Errors, report.Warnings)
			}
		})
	}
}

// 测试 20：UnpackHostDeps 按 json.Decoder 循环解多条对象（含 Imports=null）。
func TestUnpackHostDeps_DecodesStream(t *testing.T) {
	const stream = `{"ImportPath":"a","Imports":["b","c"]}
{"ImportPath":"b","Imports":null}
{"ImportPath":"c"}
`
	edges, err := UnpackHostDeps(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("UnpackHostDeps: %v", err)
	}
	if len(edges) != 3 {
		t.Fatalf("edges 数 = %d, want 3 (%v)", len(edges), edges)
	}
	if want := []string{"b", "c"}; !reflect.DeepEqual(edges["a"], want) {
		t.Errorf(`edges["a"] = %v, want %v`, edges["a"], want)
	}
	if len(edges["b"]) != 0 {
		t.Errorf(`edges["b"] = %v, want 空`, edges["b"])
	}

	// 截断/非法 JSON 必须报错，不许静默返回半截表。
	if _, err := UnpackHostDeps(strings.NewReader(`{"ImportPath":"a",`)); err == nil {
		t.Error("非法 JSON err = nil, want error")
	}
}

// 测试 21：LoadHostDeps 对真实仓库可用，且边表覆盖宿主自身。
func TestLoadHostDeps_RealRepo(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go not found in PATH: %v", err)
	}
	edges, err := LoadHostDeps("../..")
	if err != nil {
		t.Fatalf("LoadHostDeps: %v", err)
	}
	if len(edges) == 0 {
		t.Fatal("edges 为空, want 非空")
	}
	if _, ok := edges["flow-monitoring/cmd/server"]; !ok {
		t.Errorf("edges 缺 flow-monitoring/cmd/server（keys=%d）", len(edges))
	}
}

// 测试 22：真实清单 + 真实边表 ⇒ 今天的真实基线必须无违规、无告警，且确实检查了闭包。
func TestGuardHostDeps_RealRepo(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go not found in PATH: %v", err)
	}
	reg, err := registry.Load("../../registry/backend-modules")
	if err != nil {
		t.Fatalf("registry.Load: %v", err)
	}
	edges, err := LoadHostDeps("../..")
	if err != nil {
		t.Fatalf("LoadHostDeps: %v", err)
	}

	report := GuardHostDeps(reg, edges)
	if report.Checked <= 300 {
		t.Errorf("Checked = %d, want > 300（防拿空表冒充通过）", report.Checked)
	}
	if len(report.Errors) != 0 {
		t.Errorf("真实仓库 Errors = %+v, want none", report.Errors)
	}
	if len(report.Warnings) != 0 {
		t.Errorf("真实仓库 Warnings = %+v, want none", report.Warnings)
	}
}

// 测试 21：内嵌模块（InProcess）被宿主 import ⇒ 进 Warnings，不进 Errors
// （内嵌模块本就是给宿主用的库，不适用"可裁剪"概念）。
func TestGuardHostDeps_InProcessIsWarning(t *testing.T) {
	reg := newReg(t, registry.Descriptor{ID: "modules.detect", InProcess: true})
	edges := map[string][]string{
		"flow-monitoring/internal/kernel/bootstrap": {"flow-monitoring/internal/modules/detect"},
	}

	report := GuardHostDeps(reg, edges)
	if len(report.Errors) != 0 {
		t.Errorf("Errors = %+v, want none（内嵌模块只告警）", report.Errors)
	}
	if len(report.Warnings) != 1 {
		t.Fatalf("Warnings = %+v, want 1 条", report.Warnings)
	}
	got := report.Warnings[0]
	if got.ModuleID != "modules.detect" {
		t.Errorf("Warnings[0].ModuleID = %q, want modules.detect", got.ModuleID)
	}
	if want := []string{"flow-monitoring/internal/kernel/bootstrap"}; !reflect.DeepEqual(got.ImportedBy, want) {
		t.Errorf("ImportedBy = %v, want %v", got.ImportedBy, want)
	}
}
