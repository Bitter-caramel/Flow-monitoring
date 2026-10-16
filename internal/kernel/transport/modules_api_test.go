package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"flow-monitoring/internal/kernel/logging"
	"flow-monitoring/internal/kernel/modulecontrol"
	"flow-monitoring/internal/kernel/registry"
)

// ------------------------- 测试辅助（清单只写 t.TempDir，绝不碰仓库真清单） -------------------------

// writeManifest 把一个 Descriptor 写成临时清单文件。
func writeManifest(t *testing.T, dir string, d registry.Descriptor) {
	t.Helper()
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatalf("序列化清单 %s: %v", d.ID, err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(filepath.Join(dir, d.ID+".json"), b, 0o644); err != nil {
		t.Fatalf("写清单 %s: %v", d.ID, err)
	}
}

// newAPIServer 在临时清单目录上建 Service（可注入假后端），注册路由并返回 Server 与目录。
func newAPIServer(t *testing.T, ds []registry.Descriptor, rt modulecontrol.RuntimeBackend) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	for _, d := range ds {
		writeManifest(t, dir, d)
	}
	svc, err := modulecontrol.New(modulecontrol.Options{ManifestDir: dir, Runtime: rt})
	if err != nil {
		t.Fatalf("modulecontrol.New: %v", err)
	}
	s := New("127.0.0.1:0", logging.New(logging.LevelInfo, "json", io.Discard))
	if s == nil {
		t.Fatal("transport.New returned nil")
	}
	RegisterModulesAPI(s, svc)
	return s, dir
}

// do 走完整中间件链（s.Handler）发一个请求，返回状态码与响应体；不起真实监听。
func do(t *testing.T, s *Server, method, target string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读响应体: %v", err)
	}
	return resp.StatusCode, body
}

// fakeBackend 只记录调用、不做真进程操作的假运行期后端；可按模块注入错误。
type fakeBackend struct {
	states   map[string]string
	stopErr  map[string]error
	startErr map[string]error
	stops    []string
	starts   []string
}

func newFakeBackend(states map[string]string) *fakeBackend {
	if states == nil {
		states = map[string]string{}
	}
	return &fakeBackend{states: states, stopErr: map[string]error{}, startErr: map[string]error{}}
}

func (f *fakeBackend) States() map[string]string { return f.states }

func (f *fakeBackend) StopOne(_ context.Context, id string) error {
	f.stops = append(f.stops, id)
	return f.stopErr[id]
}

func (f *fakeBackend) StartOne(_ context.Context, id string) error {
	f.starts = append(f.starts, id)
	return f.startErr[id]
}

// ------------------------- 8 组契约测试 -------------------------

func TestModulesAPI(t *testing.T) {
	t.Run("1_list_unknown_state", func(t *testing.T) {
		ds := []registry.Descriptor{
			{ID: "mod.a", Name: "A", Version: "1.0.0", Layer: "L1", Provides: []string{"a.api"}},
			{ID: "mod.b", Name: "B", Version: "1.0.0", Layer: "L2", Depends: []string{"mod.a"}},
		}
		s, _ := newAPIServer(t, ds, nil)
		status, body := do(t, s, http.MethodGet, "/api/modules")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", status, body)
		}
		var views []modulecontrol.ModuleView
		if err := json.Unmarshal(body, &views); err != nil {
			t.Fatalf("解析 List: %v; body=%s", err, body)
		}
		got := map[string]string{}
		for _, v := range views {
			got[v.ID] = v.State
		}
		for _, id := range []string{"mod.a", "mod.b"} {
			if _, ok := got[id]; !ok {
				t.Errorf("List 缺少 %s: %v", id, got)
			}
		}
		for id, st := range got {
			if st != modulecontrol.StateUnknown {
				t.Errorf("无后端时 %s.State = %q, want %q", id, st, modulecontrol.StateUnknown)
			}
		}
	})

	t.Run("2_show_and_404", func(t *testing.T) {
		ds := []registry.Descriptor{{ID: "mod.a", Layer: "L1"}}
		s, _ := newAPIServer(t, ds, nil)
		status, body := do(t, s, http.MethodGet, "/api/modules/mod.a")
		if status != http.StatusOK {
			t.Fatalf("show status = %d, want 200; body=%s", status, body)
		}
		var v modulecontrol.ModuleView
		if err := json.Unmarshal(body, &v); err != nil || v.ID != "mod.a" {
			t.Fatalf("show body=%s err=%v, want id=mod.a", body, err)
		}
		status, body = do(t, s, http.MethodGet, "/api/modules/no.such.module")
		if status != http.StatusNotFound {
			t.Fatalf("不存在 status = %d, want 404; body=%s", status, body)
		}
		var e map[string]string
		if err := json.Unmarshal(body, &e); err != nil || e["error"] == "" {
			t.Fatalf("404 响应体应含 error 字段: %s", body)
		}
	})

	t.Run("3_graph", func(t *testing.T) {
		ds := []registry.Descriptor{
			{ID: "mod.a", Layer: "L1", Provides: []string{"a.api"}},
			{ID: "mod.b", Layer: "L2", Depends: []string{"mod.a"}},
		}
		s, _ := newAPIServer(t, ds, nil)
		status, body := do(t, s, http.MethodGet, "/api/modules/graph")
		if status != http.StatusOK {
			t.Fatalf("graph status = %d, want 200; body=%s", status, body)
		}
		var g modulecontrol.Graph
		if err := json.Unmarshal(body, &g); err != nil {
			t.Fatalf("解析 graph: %v; body=%s", err, body)
		}
		if len(g.Nodes) == 0 || len(g.Edges) == 0 {
			t.Fatalf("graph 应 nodes/edges 非空: %+v", g)
		}
		found := false
		for _, e := range g.Edges {
			if e.Via == "depends" || strings.HasPrefix(e.Via, "provides:") {
				found = true
			}
		}
		if !found {
			t.Errorf("edges 应含 via=depends 或 provides:*: %+v", g.Edges)
		}
	})

	t.Run("4_selfcheck", func(t *testing.T) {
		ds := []registry.Descriptor{{ID: "mod.a", Layer: "L1"}}
		s, _ := newAPIServer(t, ds, nil)
		status, body := do(t, s, http.MethodGet, "/api/modules/selfcheck")
		if status != http.StatusOK {
			t.Fatalf("selfcheck status = %d, want 200; body=%s", status, body)
		}
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("解析 selfcheck: %v; body=%s", err, body)
		}
		if _, ok := m["ok"]; !ok {
			t.Errorf("selfcheck 响应应含 ok 字段: %s", body)
		}
	})

	t.Run("5_disable_dry_run_no_write", func(t *testing.T) {
		ds := []registry.Descriptor{
			{ID: "mod.a", Layer: "L1"},
			{ID: "mod.b", Layer: "L2", Depends: []string{"mod.a"}},
		}
		s, dir := newAPIServer(t, ds, nil)
		path := filepath.Join(dir, "mod.a.json")
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读清单: %v", err)
		}
		status, body := do(t, s, http.MethodPost, "/api/modules/mod.a/disable?dry_run=1")
		if status != http.StatusOK {
			t.Fatalf("dry_run status = %d, want 200; body=%s", status, body)
		}
		var imp modulecontrol.Impact
		if err := json.Unmarshal(body, &imp); err != nil {
			t.Fatalf("解析 Impact: %v; body=%s", err, body)
		}
		if !imp.CanDisable {
			t.Errorf("mod.a 无 core 牵连，can_disable 应为 true: %+v", imp)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读清单: %v", err)
		}
		if !bytes.Equal(before, after) {
			t.Errorf("dry_run 不应改清单: before=%q after=%q", before, after)
		}
	})

	t.Run("6_disable_core_409_no_write", func(t *testing.T) {
		ds := []registry.Descriptor{
			{ID: "mod.core", Layer: "L1", Core: true},
			{ID: "mod.a", Layer: "L1"},
		}
		s, dir := newAPIServer(t, ds, nil)
		path := filepath.Join(dir, "mod.core.json")
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读清单: %v", err)
		}
		status, body := do(t, s, http.MethodPost, "/api/modules/mod.core/disable")
		if status != http.StatusConflict {
			t.Fatalf("core disable status = %d, want 409; body=%s", status, body)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读清单: %v", err)
		}
		if !bytes.Equal(before, after) {
			t.Errorf("core disable 被拒后清单不应被改")
		}
	})

	t.Run("7_disable_cascade_applied", func(t *testing.T) {
		ds := []registry.Descriptor{
			{ID: "mod.a", Layer: "L1"},
			{ID: "mod.b", Layer: "L2", Depends: []string{"mod.a"}},
		}
		rt := newFakeBackend(map[string]string{
			"mod.a": modulecontrol.StateStarted,
			"mod.b": modulecontrol.StateStarted,
		})
		s, dir := newAPIServer(t, ds, rt)
		status, body := do(t, s, http.MethodPost, "/api/modules/mod.a/disable")
		if status != http.StatusOK {
			t.Fatalf("cascade disable status = %d, want 200; body=%s", status, body)
		}
		var res modulecontrol.CascadeResult
		if err := json.Unmarshal(body, &res); err != nil {
			t.Fatalf("解析 CascadeResult: %v; body=%s", err, body)
		}
		if !res.Applied {
			t.Errorf("注入后端后 applied 应为 true: %+v", res)
		}
		if !reflect.DeepEqual(rt.stops, []string{"mod.b", "mod.a"}) {
			t.Errorf("StopOne 调用顺序 = %v, want [mod.b mod.a]", rt.stops)
		}
		if len(res.Failed) != 0 {
			t.Errorf("不应有失败: %v", res.Failed)
		}
		reg, err := registry.Load(dir)
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		if d, ok := reg.Get("mod.a"); !ok || d.IsEnabled() {
			t.Errorf("mod.a 应写回 enabled=false")
		}
	})

	t.Run("8_disable_partial_failure_not_masked", func(t *testing.T) {
		ds := []registry.Descriptor{
			{ID: "mod.a", Layer: "L1"},
			{ID: "mod.b", Layer: "L2", Depends: []string{"mod.a"}},
		}
		rt := newFakeBackend(nil)
		rt.stopErr["mod.b"] = errors.New("stop mod.b 失败")
		s, _ := newAPIServer(t, ds, rt)
		status, body := do(t, s, http.MethodPost, "/api/modules/mod.a/disable")
		if status != http.StatusOK {
			t.Fatalf("部分失败应仍 200, got %d; body=%s", status, body)
		}
		var res modulecontrol.CascadeResult
		if err := json.Unmarshal(body, &res); err != nil {
			t.Fatalf("解析 CascadeResult: %v; body=%s", err, body)
		}
		if len(res.Failed) == 0 {
			t.Errorf("某步失败时 failed 必须非空（不许伪装成全成功）: %+v", res)
		}
		sawFail := false
		for _, st := range res.Steps {
			if !st.OK {
				sawFail = true
			}
		}
		if !sawFail {
			t.Errorf("steps 应含 ok=false 的那步: %+v", res.Steps)
		}
	})
}
