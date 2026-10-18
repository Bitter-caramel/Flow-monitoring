package plugin

import "testing"

// TestRuntimeHealthDefaultsHealthy 是兼容性回归守卫：
// 未设置 OnHealth 的既有模块，Health 仍恒返回 healthy。
func TestRuntimeHealthDefaultsHealthy(t *testing.T) {
	rt := &Runtime{}
	st := rt.Health()
	if !st.Healthy {
		t.Fatalf("Health() = %+v，期望 Healthy=true", st)
	}
	if st.Message != "" {
		t.Errorf("Health().Message = %q，期望空", st.Message)
	}
}

// TestRuntimeHealthUsesOnHealth 验证 OnHealth 钩子生效。
func TestRuntimeHealthUsesOnHealth(t *testing.T) {
	rt := &Runtime{OnHealth: func() HealthStatus {
		return HealthStatus{Healthy: false, Message: "boom"}
	}}
	st := rt.Health()
	if st.Healthy {
		t.Fatalf("Health() = %+v，期望 Healthy=false", st)
	}
	if st.Message != "boom" {
		t.Errorf("Health().Message = %q，期望 boom", st.Message)
	}
}
