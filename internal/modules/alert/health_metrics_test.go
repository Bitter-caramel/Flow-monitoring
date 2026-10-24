package alert

import "testing"

// TestHealthMetricsIncludesExpectedKeys 验证 alert.health() 的 Metrics
// 含约定键（未启动时各计数为 0）。
func TestHealthMetricsIncludesExpectedKeys(t *testing.T) {
	m := &alertModule{started: true}
	st := m.health()
	if !st.Healthy {
		t.Fatalf("health = %+v, 期望 Healthy=true", st)
	}
	for _, k := range []string{"delivered", "gaps", "errors", "written", "suppressed"} {
		v, ok := st.Metrics[k]
		if !ok {
			t.Errorf("Metrics 缺少键 %q", k)
			continue
		}
		if v != "0" {
			t.Errorf("Metrics[%q] = %q, want 0", k, v)
		}
	}
}
