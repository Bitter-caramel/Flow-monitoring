package modulestatus

import (
	"encoding/json"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/eventbus"
	"flow-monitoring/pkg/plugin"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待超时：%s", what)
}

// TestStoreReceivesStatus 验证订阅到一条 module.status 后 Get/All 均正确。
func TestStoreReceivesStatus(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	s := New()
	s.Start(bus, plugin.StatusTopic)
	defer s.Stop()

	payload := `{"module_id":"modules.capture","healthy":true,"message":"",` +
		`"metrics":{"packets_total":"12","alerts_total":"3"},"at":"2024-01-02T03:04:05Z"}`
	if err := bus.Publish(plugin.StatusTopic, json.RawMessage(payload)); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	waitFor(t, "Get(modules.capture)", func() bool {
		_, ok := s.Get("modules.capture")
		return ok
	})

	st, ok := s.Get("modules.capture")
	if !ok {
		t.Fatal("Get(modules.capture) 未命中")
	}
	if !st.Healthy {
		t.Errorf("Healthy = false, want true")
	}
	if st.Metrics["packets_total"] != "12" || st.Metrics["alerts_total"] != "3" {
		t.Errorf("Metrics = %v, want packets_total=12 alerts_total=3", st.Metrics)
	}
	if st.ReceivedAt.IsZero() {
		t.Error("ReceivedAt 为空")
	}

	all := s.All()
	if len(all) != 1 {
		t.Fatalf("All() 长度 = %d, want 1", len(all))
	}
	if _, ok := all["modules.capture"]; !ok {
		t.Error("All() 不包含 modules.capture")
	}
}

// TestStoreIgnoresBadPayload 验证坏载荷被静默忽略，不 panic、不入表。
func TestStoreIgnoresBadPayload(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()
	s := New()
	s.Start(bus, plugin.StatusTopic)
	defer s.Stop()

	_ = bus.Publish(plugin.StatusTopic, json.RawMessage(`not-json`))
	_ = bus.Publish(plugin.StatusTopic, json.RawMessage(`{"healthy":true}`)) // 缺 module_id
	time.Sleep(30 * time.Millisecond)
	if all := s.All(); len(all) != 0 {
		t.Fatalf("坏载荷不应入表，All() = %v", all)
	}
}

// TestGetReturnsCopy 验证 Get/All 返回的 metrics 是副本。
func TestGetReturnsCopy(t *testing.T) {
	s := New()
	s.statuses["m"] = Status{ModuleID: "m", Metrics: map[string]string{"k": "v"}}

	st, _ := s.Get("m")
	st.Metrics["k"] = "mutated"
	st2, _ := s.Get("m")
	if st2.Metrics["k"] != "v" {
		t.Fatalf("Get 未返回副本：内部值被改成 %q", st2.Metrics["k"])
	}
}
