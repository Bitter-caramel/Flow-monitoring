package modulecontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"flow-monitoring/internal/kernel/registry"
)

// ------------------------- 测试辅助 -------------------------

func boolPtr(b bool) *bool { return &b }

// writeManifest 把一个 Descriptor 写成临时清单文件。
func writeManifest(t *testing.T, dir, name string, d registry.Descriptor) {
	t.Helper()
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatalf("序列化清单 %s: %v", name, err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		t.Fatalf("写清单 %s: %v", name, err)
	}
}

// newTestService 在 t.TempDir() 造清单并构造服务（绝不碰仓库真清单）。
func newTestService(t *testing.T, ds ...registry.Descriptor) *Service {
	t.Helper()
	dir := t.TempDir()
	for i, d := range ds {
		name := d.ID + ".json"
		if d.ID == "" {
			name = fmt.Sprintf("m%d.json", i)
		}
		writeManifest(t, dir, name, d)
	}
	s, err := New(Options{ManifestDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// assertNoTempFiles 断言目录里只剩 *.json（无 .fmctl-*.tmp 残留）。
func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range ents {
		if filepath.Ext(e.Name()) != ".json" {
			t.Errorf("目录残留非清单文件: %s", e.Name())
		}
	}
}

// ------------------------- 1. List / Show -------------------------

func TestListAndShow(t *testing.T) {
	s := newTestService(t,
		registry.Descriptor{ID: "mod.a", Name: "甲", Version: "1.0.0", Layer: "L1",
			Enabled: boolPtr(false), Provides: []string{"a.api"}, Binary: "a-bin"},
		registry.Descriptor{ID: "mod.b", Name: "乙", Version: "2.0.0", Layer: "L2"},
	)

	got, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List 长度 = %d, want 2", len(got))
	}
	if got[0].ID != "mod.a" || got[1].ID != "mod.b" {
		t.Fatalf("List 未按 ID 升序: %v, %v", got[0].ID, got[1].ID)
	}
	// Enabled==nil 视为启用；显式 false 才是停用。
	if got[0].Enabled {
		t.Errorf("mod.a.Enabled = true, want false（显式 enabled=false）")
	}
	if !got[1].Enabled {
		t.Errorf("mod.b.Enabled = false, want true（缺省启用）")
	}
	// State 本步恒为 unknown。
	for _, v := range got {
		if v.State != StateUnknown {
			t.Errorf("%s.State = %q, want %q", v.ID, v.State, StateUnknown)
		}
	}
	if got[0].Name != "甲" || got[0].Version != "1.0.0" || got[0].Layer != "L1" {
		t.Errorf("mod.a 字段错误: %+v", got[0])
	}
	if !reflect.DeepEqual(got[0].Provides, []string{"a.api"}) {
		t.Errorf("mod.a.Provides = %v", got[0].Provides)
	}
	if got[0].Binary != "a-bin" {
		t.Errorf("mod.a.Binary = %q, want a-bin", got[0].Binary)
	}

	// Show 命中：Binary 缺省回落为 ID。
	v, err := s.Show("mod.b")
	if err != nil {
		t.Fatalf("Show(mod.b): %v", err)
	}
	if v.ID != "mod.b" || v.Binary != "mod.b" || !v.Enabled || v.State != StateUnknown {
		t.Errorf("Show(mod.b) = %+v", v)
	}

	// Show 未命中 ⇒ ErrNotFound。
	if _, err := s.Show("不存在"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Show(不存在) err = %v, want ErrNotFound", err)
	}
}

// ------------------------- 2. Graph -------------------------

func TestGraph(t *testing.T) {
	s := newTestService(t,
		registry.Descriptor{ID: "mod.provider", Provides: []string{"cap.x"}, Layer: "L1"},
		registry.Descriptor{ID: "mod.consumer", Injects: []string{"cap.x"}, Layer: "L2"},
		registry.Descriptor{ID: "mod.dependent", Depends: []string{"mod.consumer"}, Layer: "L2"},
		registry.Descriptor{ID: "mod.self", Provides: []string{"cap.self"}, Injects: []string{"cap.self"}},
		registry.Descriptor{ID: "mod.missing", Depends: []string{"mod.nope"}},
		registry.Descriptor{ID: "mod.g", Provides: []string{"cap.g"}},
	)

	g, err := s.Graph()
	if err != nil {
		t.Fatalf("Graph: %v", err)
	}

	// Nodes 按 ID 升序。
	var ids []string
	for _, n := range g.Nodes {
		ids = append(ids, n.ID)
	}
	wantIDs := []string{"mod.consumer", "mod.dependent", "mod.g", "mod.missing", "mod.provider", "mod.self"}
	if !reflect.DeepEqual(ids, wantIDs) {
		t.Errorf("Nodes 顺序 = %v, want %v", ids, wantIDs)
	}

	// 两种 Via 都出现；自依赖被跳过；指向不存在模块的边被跳过。
	wantEdges := []Edge{
		{From: "mod.consumer", To: "mod.provider", Via: "provides:cap.x"},
		{From: "mod.dependent", To: "mod.consumer", Via: "depends"},
	}
	if !reflect.DeepEqual(g.Edges, wantEdges) {
		t.Errorf("Edges = %+v, want %+v", g.Edges, wantEdges)
	}
	for _, e := range g.Edges {
		if e.From == e.To {
			t.Errorf("出现自依赖边: %+v", e)
		}
		if e.To == "mod.nope" {
			t.Errorf("出现指向不存在模块的边: %+v", e)
		}
	}

	// 重复调用结果稳定（确定性排序）。
	g2, _ := s.Graph()
	if !reflect.DeepEqual(g, g2) {
		t.Errorf("Graph 两次结果不一致")
	}
}

// ------------------------- 3. Impact -------------------------

func TestImpactChain(t *testing.T) {
	// C 依赖 B，B 依赖 A（A → B → C）。
	s := newTestService(t,
		registry.Descriptor{ID: "mod.a", Layer: "L1"},
		registry.Descriptor{ID: "mod.b", Layer: "L2", Depends: []string{"mod.a"}},
		registry.Descriptor{ID: "mod.c", Depends: []string{"mod.b"}},
	)

	imp, err := s.Impact("mod.a")
	if err != nil {
		t.Fatalf("Impact(mod.a): %v", err)
	}
	// 反向拓扑序：先关最末端消费者 C，再 B；A 不在列表里。
	if !reflect.DeepEqual(imp.Dependents, []string{"mod.c", "mod.b"}) {
		t.Errorf("Impact(mod.a).Dependents = %v, want [mod.c mod.b]", imp.Dependents)
	}
	if !imp.CanDisable {
		t.Errorf("普通模块 mod.a 应可停用: %+v", imp)
	}

	impC, err := s.Impact("mod.c")
	if err != nil {
		t.Fatalf("Impact(mod.c): %v", err)
	}
	if len(impC.Dependents) != 0 {
		t.Errorf("Impact(mod.c).Dependents = %v, want 空", impC.Dependents)
	}

	if _, err := s.Impact("不存在"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Impact(不存在) err = %v, want ErrNotFound", err)
	}
}

func TestImpactCore(t *testing.T) {
	s := newTestService(t,
		registry.Descriptor{ID: "mod.core", Core: true, Layer: "L1"},
	)
	imp, err := s.Impact("mod.core")
	if err != nil {
		t.Fatalf("Impact(mod.core): %v", err)
	}
	if imp.CanDisable {
		t.Errorf("core 模块应不可停用: %+v", imp)
	}
	if imp.BlockReason == "" {
		t.Errorf("core 模块 BlockReason 不应为空")
	}
}

func TestImpactCoreDependent(t *testing.T) {
	// x ← y ← core2：停 x 会连带停掉核心模块 core2，必须拒绝。
	s := newTestService(t,
		registry.Descriptor{ID: "mod.x", Layer: "L1"},
		registry.Descriptor{ID: "mod.y", Layer: "L2", Depends: []string{"mod.x"}},
		registry.Descriptor{ID: "mod.core2", Core: true, Layer: "L2", Depends: []string{"mod.y"}},
	)
	imp, err := s.Impact("mod.x")
	if err != nil {
		t.Fatalf("Impact(mod.x): %v", err)
	}
	if imp.CanDisable {
		t.Errorf("停它会连带停掉 core，应不可停用: %+v", imp)
	}
	if !strings.Contains(imp.BlockReason, "mod.core2") {
		t.Errorf("BlockReason 应含核心模块 id mod.core2: %q", imp.BlockReason)
	}
	// 关闭顺序：core2 先于 y。
	if !reflect.DeepEqual(imp.Dependents, []string{"mod.core2", "mod.y"}) {
		t.Errorf("Dependents = %v, want [mod.core2 mod.y]", imp.Dependents)
	}
}

func TestImpactHasBinary(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "yes.json", registry.Descriptor{ID: "mod.yes", Binary: "yes-bin"})
	writeManifest(t, dir, "no.json", registry.Descriptor{ID: "mod.no", Binary: "no-bin"})

	s, err := New(Options{
		ManifestDir:   dir,
		BinaryChecker: func(binary string) bool { return binary == "yes-bin" },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	impYes, err := s.Impact("mod.yes")
	if err != nil {
		t.Fatalf("Impact(mod.yes): %v", err)
	}
	if !impYes.HasBinary {
		t.Errorf("mod.yes 有二进制时 HasBinary = false, want true: %+v", impYes)
	}

	impNo, err := s.Impact("mod.no")
	if err != nil {
		t.Fatalf("Impact(mod.no): %v", err)
	}
	if impNo.HasBinary {
		t.Errorf("mod.no 无二进制时 HasBinary = true, want false: %+v", impNo)
	}

	// 未注入 BinaryChecker（nil）：不可判定，只填 false，且不得 panic。
	sNil, err := New(Options{ManifestDir: dir})
	if err != nil {
		t.Fatalf("New(nil checker): %v", err)
	}
	impNil, err := sNil.Impact("mod.yes")
	if err != nil {
		t.Fatalf("Impact(mod.yes) with nil checker: %v", err)
	}
	if impNil.HasBinary {
		t.Errorf("BinaryChecker 为 nil 时 HasBinary = true, want false: %+v", impNil)
	}
}

// ------------------------- 4. SetEnabled -------------------------

func TestSetEnabled(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "core.json", registry.Descriptor{ID: "mod.core", Core: true, Layer: "L1"})
	writeManifest(t, dir, "x.json", registry.Descriptor{ID: "mod.x", Layer: "L2", Enabled: boolPtr(false)})

	s, err := New(Options{ManifestDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// (a) core 禁用 ⇒ ErrCoreModule，且文件字节未变。
	corePath := filepath.Join(dir, "core.json")
	before, err := os.ReadFile(corePath)
	if err != nil {
		t.Fatalf("读 core.json: %v", err)
	}
	if _, err := s.SetEnabled("mod.core", false); !errors.Is(err, ErrCoreModule) {
		t.Fatalf("SetEnabled(core,false) err = %v, want ErrCoreModule", err)
	}
	after, err := os.ReadFile(corePath)
	if err != nil {
		t.Fatalf("重读 core.json: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("核心模块文件被意外修改")
	}

	// (b) 普通模块禁用 ⇒ 写回且可重新 Load 读到 false；RestartHint 非空。
	res, err := s.SetEnabled("mod.x", false)
	if err != nil {
		t.Fatalf("SetEnabled(mod.x,false): %v", err)
	}
	if res.ID != "mod.x" || res.Enabled {
		t.Errorf("ChangeResult = %+v", res)
	}
	if res.RestartHint == "" {
		t.Errorf("RestartHint 不应为空")
	}
	reg, err := registry.Load(dir)
	if err != nil {
		t.Fatalf("重新 Load: %v", err)
	}
	if d, ok := reg.Get("mod.x"); !ok || d.IsEnabled() {
		t.Errorf("重新 Load 后 mod.x.IsEnabled() = %v, want false", d.IsEnabled())
	}

	// (c) 再启用 ⇒ 可读到 true。
	if _, err := s.SetEnabled("mod.x", true); err != nil {
		t.Fatalf("SetEnabled(mod.x,true): %v", err)
	}
	reg, _ = registry.Load(dir)
	if d, ok := reg.Get("mod.x"); !ok || !d.IsEnabled() {
		t.Errorf("重新 Load 后 mod.x.IsEnabled() = %v, want true", d.IsEnabled())
	}

	// (d) 服务层缓存已刷新。
	got, _ := s.Show("mod.x")
	if !got.Enabled {
		t.Errorf("服务缓存未刷新: Show(mod.x).Enabled = false")
	}

	// (e) 不存在 ⇒ ErrNotFound。
	if _, err := s.SetEnabled("不存在", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetEnabled(不存在) err = %v, want ErrNotFound", err)
	}

	// (f) 目录里没有临时文件残留。
	assertNoTempFiles(t, dir)
}

// TestSetEnabledInProcess 守的是"内嵌模块两个方向都拦，且不写坏清单"。
//
// 内嵌模块（inprocess）随宿主进程运行，没有独立进程可启停，写 enabled 无意义。
// SetEnabled 必须对 enabled=true / false 两个方向都返回 ErrInProcessModule，
// 且磁盘上的清单字节原样不动。
func TestSetEnabledInProcess(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "detect.json", registry.Descriptor{ID: "modules.detect", InProcess: true, Layer: "L1"})
	writeManifest(t, dir, "x.json", registry.Descriptor{ID: "mod.x", Layer: "L2", Enabled: boolPtr(false)})

	s, err := New(Options{ManifestDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	detectPath := filepath.Join(dir, "detect.json")
	before, err := os.ReadFile(detectPath)
	if err != nil {
		t.Fatalf("读 detect.json: %v", err)
	}

	// (a) 启用方向 ⇒ ErrInProcessModule。
	if _, err := s.SetEnabled("modules.detect", true); !errors.Is(err, ErrInProcessModule) {
		t.Fatalf("SetEnabled(modules.detect,true) err = %v, want ErrInProcessModule", err)
	}
	// (b) 停用方向同样拦 ⇒ ErrInProcessModule。
	if _, err := s.SetEnabled("modules.detect", false); !errors.Is(err, ErrInProcessModule) {
		t.Fatalf("SetEnabled(modules.detect,false) err = %v, want ErrInProcessModule", err)
	}
	// (c) 两个方向都试过之后磁盘字节仍未变。
	after, err := os.ReadFile(detectPath)
	if err != nil {
		t.Fatalf("重读 detect.json: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("内嵌模块文件被意外修改")
	}
	assertNoTempFiles(t, dir)

	// (d) 回归对照：普通非 core 模块的 SetEnabled 行为保持不变。
	if _, err := s.SetEnabled("mod.x", true); err != nil {
		t.Fatalf("SetEnabled(mod.x,true): %v", err)
	}
	reg, err := registry.Load(dir)
	if err != nil {
		t.Fatalf("重新 Load: %v", err)
	}
	if d, ok := reg.Get("mod.x"); !ok || !d.IsEnabled() {
		t.Errorf("mod.x.IsEnabled() = %v, want true", d.IsEnabled())
	}
}

// ------------------------- 5. round-trip 守卫（只读真实清单） -------------------------

// ------------------------- 6. 就地改值（★ 只改 enabled 的值，其余字节原样） -------------------------

// TestSetEnabledInPlacePreservesBytes 守的是"写回清单只动 enabled 的值"。
//
// ★ 夹具刻意做成"真实清单的样子"：CRLF 行尾、非规范字段顺序（binary 在 provides 前）、
// 内联数组、以及一个 **Descriptor 不认识的字段**（future_field）——
// 整体重写（json.MarshalIndent）会把这四样全部破坏或丢掉，就地改值必须一样都不动。
func TestSetEnabledInPlacePreservesBytes(t *testing.T) {
	dir := t.TempDir()
	orig := "{\r\n" +
		`  "id": "modules.rule",` + "\r\n" +
		`  "name": "规则",` + "\r\n" +
		`  "version": "0.1.0",` + "\r\n" +
		`  "layer": "L1",` + "\r\n" +
		`  "enabled": true,` + "\r\n" +
		`  "binary": "rule",` + "\r\n" +
		`  "future_field": {"keep": "me"},` + "\r\n" +
		`  "provides": ["rule.model"]` + "\r\n" +
		"}\r\n"
	path := filepath.Join(dir, "rule.json")
	if err := os.WriteFile(path, []byte(orig), 0o644); err != nil {
		t.Fatalf("写夹具: %v", err)
	}

	svc, err := New(Options{ManifestDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := svc.SetEnabled("modules.rule", false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读回: %v", err)
	}
	// ★ 精确不变量：写后字节 == 原文把 "enabled": true 换成 "enabled": false（只此一处）。
	want := strings.Replace(orig, `"enabled": true`, `"enabled": false`, 1)
	if string(got) != want {
		t.Errorf("写回结果不是「只改 enabled 值」\n原: %q\n写后: %q\n期望: %q", orig, got, want)
	}
	if n := strings.Count(string(got), "\r\n"); n != strings.Count(orig, "\r\n") {
		t.Errorf("CRLF 数变了: 原 %d, 写后 %d（行尾风格必须保留）", strings.Count(orig, "\r\n"), n)
	}
	if !strings.Contains(string(got), "future_field") {
		t.Errorf("Descriptor 不认识的字段 future_field 被丢掉了")
	}
	reg, err := registry.Load(dir)
	if err != nil {
		t.Fatalf("重新 Load: %v", err)
	}
	if d, ok := reg.Get("modules.rule"); !ok || d.IsEnabled() {
		t.Errorf("写回后 Load 结果不对: ok=%v enabled=%v", ok, d.IsEnabled())
	}
}

// TestSetEnabledRealManifestsRoundTrip 拿仓库**真实** 13 份清单的副本做回环：
// 先翻到相反状态、再翻回来 ⇒ 文件必须与原文**逐字节一致**（否则就是把清单弄脏了）。
// 只挑非核心模块翻转（核心模块禁止禁用）。
func TestSetEnabledRealManifestsRoundTrip(t *testing.T) {
	srcDir := filepath.Join("..", "..", "..", "registry", "backend-modules")
	dstDir := t.TempDir()

	entries, err := os.ReadDir(srcDir)
	if err != nil {
		t.Fatalf("读真实清单目录 %s: %v", srcDir, err)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(srcDir, e.Name()))
		if err != nil {
			t.Fatalf("读 %s: %v", e.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(dstDir, e.Name()), raw, 0o644); err != nil {
			t.Fatalf("复制 %s: %v", e.Name(), err)
		}
		n++
	}
	if n != 13 {
		t.Fatalf("真实清单数量 = %d, want 13", n)
	}

	svc, err := New(Options{ManifestDir: dstDir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	views, err := svc.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, v := range views {
		if v.Core {
			continue // 核心模块禁止禁用，跳过（另有用例覆盖）
		}
		if v.InProcess {
			continue // 内嵌模块随宿主运行，setenabled 两方向都被拦（另有用例覆盖）
		}
		path, err := svc.manifestFileForID(v.ID)
		if err != nil {
			t.Fatalf("定位 %s 的清单文件: %v", v.ID, err)
		}
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读 %s: %v", path, err)
		}
		target := !v.Enabled
		if _, err := svc.SetEnabled(v.ID, target); err != nil {
			t.Fatalf("SetEnabled(%s,%v): %v", v.ID, target, err)
		}
		if _, err := svc.SetEnabled(v.ID, v.Enabled); err != nil {
			t.Fatalf("SetEnabled(%s,%v) 回翻: %v", v.ID, v.Enabled, err)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("回读 %s: %v", path, err)
		}
		if !bytes.Equal(before, after) {
			t.Errorf("%s: 翻两次后与原文件不一致（清单被弄脏）\n原: %q\n后: %q", v.ID, before, after)
		}
	}
}

func TestNewMissingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	if _, err := New(Options{ManifestDir: missing}); err == nil {
		t.Fatalf("New 目录不存在时应返回错误")
	} else if !strings.Contains(err.Error(), missing) {
		t.Errorf("错误信息应含路径 %s, got %v", missing, err)
	}
}

// ------------------------- 7. 级联启停（★ 全用假 backend，不碰真进程） -------------------------

// fakeRuntime 只记录调用、不做真进程操作的假后端；可按模块注入错误。
type fakeRuntime struct {
	states   map[string]string
	stopErr  map[string]error
	startErr map[string]error
	stops    []string
	starts   []string
}

func newFakeRuntime(states map[string]string) *fakeRuntime {
	if states == nil {
		states = map[string]string{}
	}
	return &fakeRuntime{states: states, stopErr: map[string]error{}, startErr: map[string]error{}}
}

func (f *fakeRuntime) States() map[string]string { return f.states }

func (f *fakeRuntime) StopOne(_ context.Context, id string) error {
	f.stops = append(f.stops, id)
	return f.stopErr[id]
}

func (f *fakeRuntime) StartOne(_ context.Context, id string) error {
	f.starts = append(f.starts, id)
	return f.startErr[id]
}

// TestStateFromRuntime：List/Show 的 State——装后端取后端值、未出现的给 unknown；不装仍 unknown。
func TestStateFromRuntime(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "a.json", registry.Descriptor{ID: "mod.a", Layer: "L1"})
	writeManifest(t, dir, "b.json", registry.Descriptor{ID: "mod.b", Layer: "L2"})

	// (a) 无后端 ⇒ 恒 unknown。
	s, err := New(Options{ManifestDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v, _ := s.Show("mod.a"); v.State != StateUnknown {
		t.Errorf("无后端 Show(mod.a).State = %q, want %q", v.State, StateUnknown)
	}
	views, _ := s.List()
	for _, mv := range views {
		if mv.State != StateUnknown {
			t.Errorf("无后端 List %s.State = %q, want unknown", mv.ID, mv.State)
		}
	}

	// (b) Options.Runtime ⇒ 取到后端值；未出现的模块给 unknown。
	rt := newFakeRuntime(map[string]string{"mod.a": StateStarted})
	s2, err := New(Options{ManifestDir: dir, Runtime: rt})
	if err != nil {
		t.Fatalf("New(runtime): %v", err)
	}
	va, err := s2.Show("mod.a")
	if err != nil {
		t.Fatalf("Show(mod.a): %v", err)
	}
	if va.State != StateStarted {
		t.Errorf("有后端 Show(mod.a).State = %q, want %q", va.State, StateStarted)
	}
	if vb, _ := s2.Show("mod.b"); vb.State != StateUnknown {
		t.Errorf("后端未给出 mod.b ⇒ State = %q, want unknown", vb.State)
	}
	listStates := map[string]string{}
	lv, _ := s2.List()
	for _, mv := range lv {
		listStates[mv.ID] = mv.State
	}
	if listStates["mod.a"] != StateStarted || listStates["mod.b"] != StateUnknown {
		t.Errorf("List 的 State = %v, want a=started b=unknown", listStates)
	}

	// (c) WithRuntime 注入同样生效（换一个后端值）。
	s2.WithRuntime(newFakeRuntime(map[string]string{"mod.b": StateStopped}))
	if vb, _ := s2.Show("mod.b"); vb.State != StateStopped {
		t.Errorf("WithRuntime 后 Show(mod.b).State = %q, want %q", vb.State, StateStopped)
	}
}

// TestSetEnabledCascadeOrder：★ 级联顺序必须是反向拓扑序（先关最末端消费者，最后目标）。
func TestSetEnabledCascadeOrder(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "a.json", registry.Descriptor{ID: "mod.a", Layer: "L1"})
	writeManifest(t, dir, "b.json", registry.Descriptor{ID: "mod.b", Layer: "L2", Depends: []string{"mod.a"}})
	writeManifest(t, dir, "c.json", registry.Descriptor{ID: "mod.c", Layer: "L3", Depends: []string{"mod.b"}})

	rt := newFakeRuntime(map[string]string{"mod.a": StateStarted, "mod.b": StateStarted, "mod.c": StateStarted})
	s, err := New(Options{ManifestDir: dir, Runtime: rt})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := s.SetEnabledCascade(context.Background(), "mod.a", false)
	if err != nil {
		t.Fatalf("SetEnabledCascade(mod.a,false): %v", err)
	}

	// ★ Steps 顺序必须是 C、B、A（先停最末端消费者，最后目标）。
	var gotOrder []string
	for _, st := range res.Steps {
		gotOrder = append(gotOrder, st.ID)
		if st.Action != "stop" || !st.OK {
			t.Errorf("Step %+v, want action=stop ok=true", st)
		}
	}
	if !reflect.DeepEqual(gotOrder, []string{"mod.c", "mod.b", "mod.a"}) {
		t.Errorf("Steps 顺序 = %v, want [mod.c mod.b mod.a]", gotOrder)
	}
	if !reflect.DeepEqual(rt.stops, []string{"mod.c", "mod.b", "mod.a"}) {
		t.Errorf("后端 StopOne 调用顺序 = %v, want [mod.c mod.b mod.a]", rt.stops)
	}
	if len(rt.starts) != 0 {
		t.Errorf("停用过程不应调用 StartOne: %v", rt.starts)
	}
	if !res.Applied {
		t.Errorf("有后端时 Applied 应为 true")
	}
	if !reflect.DeepEqual(res.Stopped, []string{"mod.c", "mod.b", "mod.a"}) {
		t.Errorf("Stopped = %v, want [mod.c mod.b mod.a]", res.Stopped)
	}
	// 清单：mod.a 已禁用。
	reg, _ := registry.Load(dir)
	if d, ok := reg.Get("mod.a"); !ok || d.IsEnabled() {
		t.Errorf("mod.a 应已写回 enabled=false")
	}
}

// TestSetEnabledCascadeCoreProtection：core 目标 / 连带停 core ⇒ 拒绝且不动任何东西。
func TestSetEnabledCascadeCoreProtection(t *testing.T) {
	// (a) 目标 core ⇒ ErrCoreModule。
	dir := t.TempDir()
	writeManifest(t, dir, "core.json", registry.Descriptor{ID: "mod.core", Core: true, Layer: "L1"})
	corePath := filepath.Join(dir, "core.json")
	before, _ := os.ReadFile(corePath)

	rt := newFakeRuntime(nil)
	s, err := New(Options{ManifestDir: dir, Runtime: rt})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.SetEnabledCascade(context.Background(), "mod.core", false); !errors.Is(err, ErrCoreModule) {
		t.Fatalf("err = %v, want ErrCoreModule", err)
	}
	if len(rt.stops) != 0 || len(rt.starts) != 0 {
		t.Errorf("core 被拒时不应调用后端: stops=%v starts=%v", rt.stops, rt.starts)
	}
	if after, _ := os.ReadFile(corePath); !bytes.Equal(before, after) {
		t.Errorf("core 清单被意外修改")
	}

	// (b) 目标非 core 但"连带会停 core" ⇒ 返回错误、后端一次都没调用、清单字节未变。
	dir2 := t.TempDir()
	writeManifest(t, dir2, "x.json", registry.Descriptor{ID: "mod.x", Layer: "L1"})
	writeManifest(t, dir2, "y.json", registry.Descriptor{ID: "mod.y", Layer: "L2", Depends: []string{"mod.x"}})
	writeManifest(t, dir2, "core2.json", registry.Descriptor{ID: "mod.core2", Core: true, Layer: "L3", Depends: []string{"mod.y"}})
	xPath := filepath.Join(dir2, "x.json")
	xBefore, _ := os.ReadFile(xPath)

	rt2 := newFakeRuntime(nil)
	s2, err := New(Options{ManifestDir: dir2, Runtime: rt2})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s2.SetEnabledCascade(context.Background(), "mod.x", false); err == nil {
		t.Fatalf("连带停 core 应返回错误")
	} else if !strings.Contains(err.Error(), "mod.core2") {
		t.Errorf("错误信息应含 BlockReason 里的 core 模块 mod.core2: %v", err)
	}
	if len(rt2.stops) != 0 || len(rt2.starts) != 0 {
		t.Errorf("被拒时不应调用后端: stops=%v starts=%v", rt2.stops, rt2.starts)
	}
	if xAfter, _ := os.ReadFile(xPath); !bytes.Equal(xBefore, xAfter) {
		t.Errorf("被拒时清单不应被修改")
	}

	// (c) 不存在 ⇒ ErrNotFound，且不调用后端。
	if _, err := s2.SetEnabledCascade(context.Background(), "不存在", false); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// TestSetEnabledCascadeFailureAccounting：★ 某步失败不吞——记 Failed、继续其余、清单仍写。
func TestSetEnabledCascadeFailureAccounting(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "a.json", registry.Descriptor{ID: "mod.a", Layer: "L1"})
	writeManifest(t, dir, "b.json", registry.Descriptor{ID: "mod.b", Layer: "L2", Depends: []string{"mod.a"}})
	writeManifest(t, dir, "c.json", registry.Descriptor{ID: "mod.c", Layer: "L3", Depends: []string{"mod.b"}})

	rt := newFakeRuntime(map[string]string{"mod.a": StateStarted})
	rt.stopErr["mod.b"] = errors.New("boom")

	s, err := New(Options{ManifestDir: dir, Runtime: rt})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := s.SetEnabledCascade(context.Background(), "mod.a", false)
	if err != nil {
		t.Fatalf("SetEnabledCascade: %v", err)
	}

	// ★ 其余步骤仍执行：Steps = C, B(失败), A。
	var ids []string
	for _, st := range res.Steps {
		ids = append(ids, st.ID)
	}
	if !reflect.DeepEqual(ids, []string{"mod.c", "mod.b", "mod.a"}) {
		t.Errorf("Steps 顺序 = %v, want [mod.c mod.b mod.a]", ids)
	}
	var bStep *StepResult
	for i := range res.Steps {
		if res.Steps[i].ID == "mod.b" {
			bStep = &res.Steps[i]
		}
	}
	if bStep == nil || bStep.OK || bStep.Err == "" {
		t.Errorf("mod.b 步应 OK=false 且带 Err: %+v", bStep)
	}
	if !reflect.DeepEqual(res.Failed, []string{"mod.b"}) {
		t.Errorf("Failed = %v, want [mod.b]", res.Failed)
	}
	if !reflect.DeepEqual(res.Stopped, []string{"mod.c", "mod.a"}) {
		t.Errorf("Stopped = %v, want [mod.c mod.a]", res.Stopped)
	}
	if !reflect.DeepEqual(rt.stops, []string{"mod.c", "mod.b", "mod.a"}) {
		t.Errorf("即便 B 失败也应继续停 A: %v", rt.stops)
	}
	if !res.Applied {
		t.Errorf("Applied 应为 true（清单仍写回）")
	}
	reg, _ := registry.Load(dir)
	if d, ok := reg.Get("mod.a"); !ok || d.IsEnabled() {
		t.Errorf("mod.a 应写回 enabled=false")
	}
}

// TestSetEnabledCascadeNoBackend：无后端 ⇒ Applied=false + Steps 空 + RestartHint 非空，清单仍改。
func TestSetEnabledCascadeNoBackend(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "x.json", registry.Descriptor{ID: "mod.x", Layer: "L2"})
	s, err := New(Options{ManifestDir: dir}) // 不装后端
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := s.SetEnabledCascade(context.Background(), "mod.x", false)
	if err != nil {
		t.Fatalf("SetEnabledCascade: %v", err)
	}
	if res.Applied {
		t.Errorf("无后端 Applied 应为 false")
	}
	if len(res.Steps) != 0 {
		t.Errorf("无后端 Steps 应为空: %+v", res.Steps)
	}
	if res.RestartHint != RestartHint {
		t.Errorf("RestartHint = %q, want %q", res.RestartHint, RestartHint)
	}
	reg, _ := registry.Load(dir)
	if d, ok := reg.Get("mod.x"); !ok || d.IsEnabled() {
		t.Errorf("mod.x 应写回 enabled=false")
	}
}

// TestSetEnabledCascadeEnableOnlySelf：启用只调一次 StartOne(x)，不动别的模块。
func TestSetEnabledCascadeEnableOnlySelf(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "x.json", registry.Descriptor{ID: "mod.x", Layer: "L1", Enabled: boolPtr(false)})
	writeManifest(t, dir, "y.json", registry.Descriptor{ID: "mod.y", Layer: "L2", Depends: []string{"mod.x"}})

	rt := newFakeRuntime(map[string]string{"mod.x": StateStopped})
	s, err := New(Options{ManifestDir: dir, Runtime: rt})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := s.SetEnabledCascade(context.Background(), "mod.x", true)
	if err != nil {
		t.Fatalf("SetEnabledCascade(mod.x,true): %v", err)
	}
	if !reflect.DeepEqual(rt.starts, []string{"mod.x"}) {
		t.Errorf("StartOne 调用 = %v, want [mod.x]", rt.starts)
	}
	if len(rt.stops) != 0 {
		t.Errorf("启用不应调用 StopOne: %v", rt.stops)
	}
	if len(res.Steps) != 1 || res.Steps[0].ID != "mod.x" || res.Steps[0].Action != "start" || !res.Steps[0].OK {
		t.Errorf("Steps = %+v, want 仅 mod.x start ok", res.Steps)
	}
	if !res.Applied {
		t.Errorf("有后端启用 Applied 应为 true")
	}
	reg, _ := registry.Load(dir)
	if d, ok := reg.Get("mod.x"); !ok || !d.IsEnabled() {
		t.Errorf("mod.x 应写回 enabled=true")
	}
	if d, ok := reg.Get("mod.y"); !ok || !d.IsEnabled() {
		t.Errorf("mod.y 不应被动到")
	}
}

// TestSetEnabledIgnoresRuntime：12-2 旧方法 SetEnabled 行为不变——只改清单、不调后端。
func TestSetEnabledIgnoresRuntime(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "x.json", registry.Descriptor{ID: "mod.x", Layer: "L2"})

	rt := newFakeRuntime(map[string]string{"mod.x": StateStarted})
	s, err := New(Options{ManifestDir: dir, Runtime: rt})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := s.SetEnabled("mod.x", false)
	if err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if res.RestartHint == "" || res.Enabled {
		t.Errorf("ChangeResult = %+v", res)
	}
	if len(rt.stops) != 0 || len(rt.starts) != 0 {
		t.Errorf("SetEnabled（12-2 旧方法）不应调用后端: stops=%v starts=%v", rt.stops, rt.starts)
	}
	reg, _ := registry.Load(dir)
	if d, ok := reg.Get("mod.x"); !ok || d.IsEnabled() {
		t.Errorf("mod.x 应写回 enabled=false")
	}
	assertNoTempFiles(t, dir)
}

// 测试：内嵌模块（InProcess）不可单独启停，且原因优先于 core（不被 core 覆盖）。
func TestImpactInProcess(t *testing.T) {
	s := newTestService(t,
		registry.Descriptor{ID: "modules.detect", InProcess: true, Layer: "L2"},
		// 同时是 core + inprocess：原因必须仍是"内嵌"，不能被 core 的原因覆盖。
		registry.Descriptor{ID: "modules.rule", InProcess: true, Core: true, Layer: "L1"},
	)

	imp, err := s.Impact("modules.detect")
	if err != nil {
		t.Fatalf("Impact(modules.detect): %v", err)
	}
	if !imp.InProcess {
		t.Errorf("Impact.InProcess = false, want true: %+v", imp)
	}
	if imp.CanDisable {
		t.Errorf("内嵌模块 CanDisable = true, want false: %+v", imp)
	}
	if !strings.Contains(imp.BlockReason, "内嵌") {
		t.Errorf("BlockReason 应含 '内嵌': %q", imp.BlockReason)
	}

	impCore, err := s.Impact("modules.rule")
	if err != nil {
		t.Fatalf("Impact(modules.rule): %v", err)
	}
	if impCore.CanDisable {
		t.Errorf("core+inprocess 模块 CanDisable = true, want false: %+v", impCore)
	}
	if !strings.Contains(impCore.BlockReason, "内嵌") {
		t.Errorf("BlockReason 应优先说明内嵌（不能被 core 原因覆盖）: %q", impCore.BlockReason)
	}
}
