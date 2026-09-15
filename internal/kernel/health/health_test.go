package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"flow-monitoring/internal/kernel/lifecycle"
	"flow-monitoring/internal/kernel/plugin"
	"flow-monitoring/internal/kernel/registry"
)

// testPlugin 测试用插件（可带健康探针）。
type testPlugin struct {
	plugin.Base
	id        string
	onHealth  func() plugin.HealthStatus
}

func (p *testPlugin) Manifest() plugin.Manifest {
	return plugin.Manifest{ID: p.id, Name: p.id, Version: "1.0.0", Layer: plugin.LayerKernel}
}

func (p *testPlugin) Health() plugin.HealthStatus {
	if p.onHealth != nil {
		return p.onHealth()
	}
	return plugin.HealthStatus{Healthy: true}
}

// newTestHealth 创建注册了若干插件的 Health。
func newTestHealth(plugins ...plugin.Plugin) (*Health, *registry.Registry, *lifecycle.Coordinator) {
	reg := registry.New()
	for _, p := range plugins {
		_ = reg.Register(p)
	}
	lc := lifecycle.New(reg, plugin.NewContext(context.Background()))
	return New(reg, lc), reg, lc
}

// TestReport_Empty 空平台返回 ok。
func TestReport_Empty(t *testing.T) {
	h := New(nil, nil)
	rep := h.Report()
	if rep.Status != StatusOK {
		t.Errorf("Status = %q, want ok", rep.Status)
	}
}

// TestReport_AllStarted 插件 Started 且探针健康 → ok。
func TestReport_AllStarted(t *testing.T) {
	h, _, lc := newTestHealth(&testPlugin{id: "a"}, &testPlugin{id: "b"})
	_ = lc.StartAll(context.Background())

	rep := h.Report()
	if rep.Status != StatusOK {
		t.Errorf("Status = %q, want ok", rep.Status)
	}
	if len(rep.Modules) != 2 {
		t.Fatalf("Modules len = %d, want 2", len(rep.Modules))
	}
	for _, mh := range rep.Modules {
		if mh.State != "Started" {
			t.Errorf("module %s state = %q, want Started", mh.ID, mh.State)
		}
	}
}

// TestReport_ProbeUnhealthy 探针不健康 → degraded。
func TestReport_ProbeUnhealthy(t *testing.T) {
	h, _, lc := newTestHealth(&testPlugin{
		id: "a",
		onHealth: func() plugin.HealthStatus {
			return plugin.HealthStatus{Healthy: false, Message: "db down"}
		},
	})
	_ = lc.StartAll(context.Background())

	rep := h.Report()
	if rep.Status != StatusDegraded {
		t.Errorf("Status = %q, want degraded", rep.Status)
	}
	if rep.Modules[0].Message != "db down" {
		t.Errorf("Message = %q, want 'db down'", rep.Modules[0].Message)
	}
}

// TestReport_ErrorState 插件未装配 → degraded。
func TestReport_ErrorState(t *testing.T) {
	h, _, _ := newTestHealth(&testPlugin{id: "a"})
	// 不 StartAll，状态为 Created（未装配 → unhealthy）
	rep := h.Report()
	if rep.Status != StatusDegraded {
		t.Errorf("Status = %q, want degraded", rep.Status)
	}
}

// TestHandler_StatusCode ok 返回 200。
func TestHandler_StatusCode(t *testing.T) {
	h, _, lc := newTestHealth(&testPlugin{id: "a"})
	_ = lc.StartAll(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var rep Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rep.Status != StatusOK {
		t.Errorf("report status = %q, want ok", rep.Status)
	}
}
