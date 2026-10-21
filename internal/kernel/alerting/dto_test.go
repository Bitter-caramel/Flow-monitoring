package alerting

import (
	"testing"
	"time"

	"flow-monitoring/internal/kernel/eventbus"
)

// TestAlertDecodesPktNo 宿主 DTO 必须接住 detect.feature 里的 pkt_no。
//
// ★ 这是"告警 ↔ 包"链路的第一环：capture 的 featureEvent 已经带 pkt_no，
// 若宿主 Alert 没有该字段，json.Unmarshal 会静默丢掉，前端就永远拿不到包号。
func TestAlertDecodesPktNo(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	svc := New(Config{Capacity: 10})
	svc.Start(bus, "detect.feature")
	defer svc.Stop()

	// 与 capture featureEvent 的 JSON 形状一致，额外带 pkt_no。
	payload := []byte(`{"rule_id":"r-pkt","name":"r-pkt name","severity":"high","weight":80,` +
		`"time":"2024-01-02T03:04:05Z","src_ip":"10.0.0.1","src_port":1234,` +
		`"dst_ip":"10.0.0.2","dst_port":80,"proto":"HTTP","stream_id":7,` +
		`"pkt_no":42,"buffer":"payload","offset":3,"snippet":"abc"}`)
	if err := bus.Publish("detect.feature", payload); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return svc.Stats().AlertsTotal == 1 })

	p := svc.Query(1, DefaultPageSize, 0, Filter{})
	if p.Total != 1 {
		t.Fatalf("total = %d, want 1", p.Total)
	}
	if got := p.Items[0].PktNo; got != 42 {
		t.Fatalf("PktNo = %d, want 42（事件里的 pkt_no 被丢弃）", got)
	}
}

// TestAlertPktNoOmittedForOldPayload 不含 pkt_no 的旧载荷仍能解码，PktNo 为 0。
func TestAlertPktNoOmittedForOldPayload(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	svc := New(Config{Capacity: 10})
	svc.Start(bus, "detect.feature")
	defer svc.Stop()

	if err := bus.Publish("detect.feature", alertJSON("old")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return svc.Stats().AlertsTotal == 1 })

	p := svc.Query(1, DefaultPageSize, 0, Filter{})
	if p.Total != 1 || p.Items[0].PktNo != 0 {
		t.Fatalf("旧载荷 pkt_no = %d（total=%d），want 0", p.Items[0].PktNo, p.Total)
	}
}
