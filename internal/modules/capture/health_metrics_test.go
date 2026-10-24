package capture

import "testing"

// TestHealthMetricsIncludesExpectedKeys 验证 capture.health() 的 Metrics
// 含约定键，且数值口径正确（packets/alerts 跨 Run 汇总）。
func TestHealthMetricsIncludesExpectedKeys(t *testing.T) {
	m := &captureModule{started: true}
	m.ensureRunsLocked()
	// 一个运行中、一个已结束：便于同时校验 runs_running / runs_total。
	m.runs["r1"] = &captureRun{ID: "r1", State: runStateRunning, Packets: 10, Alerts: 2}
	m.runs["r2"] = &captureRun{ID: "r2", State: runStateDone, Packets: 5, Alerts: 1}

	st := m.health()
	if !st.Healthy {
		t.Fatalf("health = %+v, 期望 Healthy=true", st)
	}
	want := map[string]string{
		"packets_total": "15",
		"alerts_total":  "3",
		"rules_total":   "0", // ruleset 为 nil
		"runs_running":  "1",
		"runs_total":    "2",
	}
	for k, v := range want {
		got, ok := st.Metrics[k]
		if !ok {
			t.Errorf("Metrics 缺少键 %q", k)
			continue
		}
		if got != v {
			t.Errorf("Metrics[%q] = %q, want %q", k, got, v)
		}
	}
}
