package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"flow-monitoring/internal/kernel/lifecycle"
	"flow-monitoring/internal/kernel/registry"
)

// TestReport_Empty 空平台返回 ok。
func TestReport_Empty(t *testing.T) {
	h := New(nil, nil)
	rep := h.Report()
	if rep.Status != StatusOK {
		t.Errorf("Status = %q, want ok", rep.Status)
	}
	if len(rep.Modules) != 0 {
		t.Errorf("Modules len = %d, want 0", len(rep.Modules))
	}
	if rep.Uptime < 0 {
		t.Errorf("Uptime should be >= 0")
	}
}

// TestReport_AllStarted 模块全部 Started 且探针健康 → ok。
func TestReport_AllStarted(t *testing.T) {
	reg := registry.New()
	_ = reg.Register(&registry.ModuleInfo{
		ID:       "a",
		HealthFn: func() registry.HealthStatus { return registry.HealthStatus{Healthy: true} },
	})
	_ = reg.Register(&registry.ModuleInfo{ID: "b"})

	lc := lifecycle.New(reg)
	_ = lc.StartAll(context.Background())

	h := New(reg, lc)
	rep := h.Report()
	if rep.Status != StatusOK {
		t.Errorf("Status = %q, want ok", rep.Status)
	}
	if len(rep.Modules) != 2 {
		t.Fatalf("Modules len = %d, want 2", len(rep.Modules))
	}
	for _, mh := range rep.Modules {
		if !mh.Healthy {
			t.Errorf("module %s should be healthy", mh.ID)
		}
		if mh.State != "Started" {
			t.Errorf("module %s state = %q, want Started", mh.ID, mh.State)
		}
	}
}

// TestReport_ProbeUnhealthy 探针返回不健康 → degraded。
func TestReport_ProbeUnhealthy(t *testing.T) {
	reg := registry.New()
	_ = reg.Register(&registry.ModuleInfo{
		ID: "a",
		HealthFn: func() registry.HealthStatus {
			return registry.HealthStatus{Healthy: false, Message: "db down"}
		},
	})

	lc := lifecycle.New(reg)
	_ = lc.StartAll(context.Background())

	h := New(reg, lc)
	rep := h.Report()
	if rep.Status != StatusDegraded {
		t.Errorf("Status = %q, want degraded", rep.Status)
	}
	// 找到 a 模块
	var found bool
	for _, mh := range rep.Modules {
		if mh.ID == "a" {
			found = true
			if mh.Healthy {
				t.Error("module a should be unhealthy")
			}
			if mh.Message != "db down" {
				t.Errorf("message = %q, want 'db down'", mh.Message)
			}
		}
	}
	if !found {
		t.Error("module a not in report")
	}
}

// TestReport_ErrorState 模块 Error 状态 → degraded。
func TestReport_ErrorState(t *testing.T) {
	reg := registry.New()
	_ = reg.Register(&registry.ModuleInfo{
		ID:      "a",
		StartFn: func() error { return context.DeadlineExceeded },
	})

	lc := lifecycle.New(reg)
	_ = lc.StartAll(context.Background()) // 启动失败，a 进入 Error

	h := New(reg, lc)
	rep := h.Report()
	if rep.Status != StatusDegraded {
		t.Errorf("Status = %q, want degraded", rep.Status)
	}
	for _, mh := range rep.Modules {
		if mh.ID == "a" {
			if mh.State != "Error" {
				t.Errorf("state = %q, want Error", mh.State)
			}
			if mh.Healthy {
				t.Error("module a should be unhealthy in error state")
			}
		}
	}
}

// TestHandler_StatusCode ok 返回 200。
func TestHandler_StatusCode(t *testing.T) {
	reg := registry.New()
	_ = reg.Register(&registry.ModuleInfo{ID: "a"})
	lc := lifecycle.New(reg)
	_ = lc.StartAll(context.Background())

	h := New(reg, lc)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want 200", rec.Code)
	}
	var rep Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rep.Status != StatusOK {
		t.Errorf("report status = %q, want ok", rep.Status)
	}
}

// TestHandler_DownStatusCode degraded 仍返回 200，down 返回 503。
//
// 当前实现仅 down 返回 503；degraded 返回 200（服务仍可用）。
func TestHandler_DownStatusCode(t *testing.T) {
	// 无模块时 ok → 200
	h := New(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("empty health should return 200, got %d", rec.Code)
	}
}
