package alerting

// 任务 15-3：告警 WebSocket 推送的宿主侧测试。
//
// 关注两点：
//   1) OnAlert 回调能收到"已分配 id"的告警（广播契约要求 data.id 有值）；
//   2) 派发通道满时 push_dropped 增长，且告警消费循环绝不被慢回调阻塞。

import (
	"encoding/json"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/eventbus"
)

// TestServiceOnAlertReceivesAssignedID SetOnAlert 注册后，总线投一条合法告警 ⇒
// 回调收到该告警且 id 已分配（入库后分配，必须与 Query 一致）。
func TestServiceOnAlertReceivesAssignedID(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	svc := New(Config{Capacity: 100, PushBuffer: 16})
	got := make(chan Alert, 4)
	svc.SetOnAlert(func(a Alert) { got <- a })
	svc.Start(bus, "detect.feature")
	defer svc.Stop()

	if err := bus.Publish("detect.feature", alertJSON("push")); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case a := <-got:
		if a.ID == 0 {
			t.Fatalf("OnAlert 回调收到 id=0，want 已分配（从 1 起）")
		}
		if a.RuleID != "push" || a.SrcIP != "10.0.0.1" || a.Snippet != "abc" {
			t.Fatalf("OnAlert 回调字段错误: %+v", a)
		}
		// 回调里的 id 必须与环形缓冲里的记录一致（分配发生在入库时）。
		if p := svc.Query(1, 10, 0); p.Total != 1 || p.Items[0].ID != a.ID {
			t.Fatalf("Query = %+v, want 与回调一致的 id=%d", p, a.ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("等待 OnAlert 回调超时")
	}
}

// TestServicePushDroppedWhenFull 回调阻塞（模拟慢客户端/慢广播）时继续投递超过
// 缓冲容量：push_dropped 必须增长，且投递必须在超时内完成（消费循环不被反压）。
func TestServicePushDroppedWhenFull(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	const capacity = 1000
	svc := New(Config{Capacity: capacity, PushBuffer: 2})
	release := make(chan struct{})
	svc.SetOnAlert(func(a Alert) { <-release }) // 卡住派发 goroutine，模拟慢客户端
	svc.Start(bus, "detect.feature")

	// 先注册清理：先放行回调，再 Stop（否则 Stop 会等回调返回而卡死）。
	defer svc.Stop()
	defer close(release)

	const n = 50
	for i := 0; i < n; i++ {
		if err := bus.Publish("detect.feature", alertJSON("slow")); err != nil {
			t.Fatalf("Publish #%d: %v", i, err)
		}
	}

	// 超时保护：若消费循环被反向阻塞，这个条件永远不成立 ⇒ waitFor 失败。
	waitFor(t, 2*time.Second, func() bool {
		st := svc.Stats()
		return st.Received == n && st.PushDropped > 0
	})

	st := svc.Stats()
	t.Logf("received=%d alerts_total=%d push_dropped=%d", st.Received, st.AlertsTotal, st.PushDropped)

	// 派发拥塞只影响推送，不能影响入库。
	if st.AlertsTotal != n {
		t.Fatalf("alerts_total = %d, want %d（入库不能因派发拥塞而丢）", st.AlertsTotal, n)
	}
}

// TestWSAlertEnvelope 锁定前后端 WS 消息契约：{"type":"alert","data":{...}}，
// data 的字段名必须与后端 Alert 的 JSON tag 一致（前端按这些名字渲染）。
func TestWSAlertEnvelope(t *testing.T) {
	a := Alert{
		ID: 1, RuleID: "suricata-1000001", Name: "test-rule", Severity: "high",
		Weight: 80, Time: "2024-01-01T08:00:00+08:00",
		SrcIP: "10.0.0.1", SrcPort: 40000, DstIP: "10.0.0.2", DstPort: 80,
		Proto: "HTTP", StreamID: 1, Buffer: "payload", Offset: 18, Snippet: "union select",
	}
	b, err := json.Marshal(map[string]any{"type": "alert", "data": a})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var env struct {
		Type string `json:"type"`
		Data Alert  `json:"data"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.Type != "alert" {
		t.Fatalf("type = %q, want alert", env.Type)
	}
	if env.Data.ID != 1 || env.Data.RuleID != "suricata-1000001" || env.Data.SrcPort != 40000 {
		t.Fatalf("data 字段解码错误: %+v", env.Data)
	}
	t.Logf("WS 消息样例: %s", b)
}
