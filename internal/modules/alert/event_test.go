package alert

import (
	"encoding/json"
	"testing"
	"time"

	"flow-monitoring/internal/modules/detect"
	"flow-monitoring/internal/modules/rule"
)

// 断言生命周期话题名固定为 alert.lifecycle，防止手滑改错。
func TestTopicName(t *testing.T) {
	if TopicAlertLifecycle != "alert.lifecycle" {
		t.Fatalf("话题名期望 %q, 实际 %q", "alert.lifecycle", TopicAlertLifecycle)
	}
}

// 断言 Event 负载可 JSON 往返且字段逐一相等（搬独立进程时直接复用）。
func TestEventJSONRoundTrip(t *testing.T) {
	src := Event{
		CaptureID: "capture.pcapng",
		Alert: detect.Alert{
			RuleID:   "r1",
			Name:     "命中",
			Severity: "high",
			Weight:   7,
			Time:     time.Unix(1700000000, 123456789).UTC(),
			SrcIP:    "10.0.0.5",
			SrcPort:  50000,
			DstIP:    "93.184.216.34",
			DstPort:  80,
			Proto:    "HTTP",
			StreamID: 3,
			PktNo:    42,
			FlowKey:  "10.0.0.5:50000->93.184.216.34:80/HTTP",
			Buffer:   rule.BufPayload,
			Offset:   4,
			Snippet:  "GET /",
		},
	}

	raw, err := json.Marshal(src)
	if err != nil {
		t.Fatalf("json.Marshal 失败: %v", err)
	}
	var dst Event
	if err := json.Unmarshal(raw, &dst); err != nil {
		t.Fatalf("json.Unmarshal 失败: %v", err)
	}

	if dst.CaptureID != src.CaptureID {
		t.Fatalf("CaptureID 期望 %q, 实际 %q", src.CaptureID, dst.CaptureID)
	}
	a, b := src.Alert, dst.Alert
	if b.RuleID != a.RuleID {
		t.Fatalf("RuleID 期望 %q, 实际 %q", a.RuleID, b.RuleID)
	}
	if b.Name != a.Name {
		t.Fatalf("Name 期望 %q, 实际 %q", a.Name, b.Name)
	}
	if b.Severity != a.Severity {
		t.Fatalf("Severity 期望 %q, 实际 %q", a.Severity, b.Severity)
	}
	if b.Weight != a.Weight {
		t.Fatalf("Weight 期望 %d, 实际 %d", a.Weight, b.Weight)
	}
	if !b.Time.Equal(a.Time) {
		t.Fatalf("Time 期望 %v, 实际 %v", a.Time, b.Time)
	}
	if b.SrcIP != a.SrcIP || b.SrcPort != a.SrcPort {
		t.Fatalf("源地址期望 %s:%d, 实际 %s:%d", a.SrcIP, a.SrcPort, b.SrcIP, b.SrcPort)
	}
	if b.DstIP != a.DstIP || b.DstPort != a.DstPort {
		t.Fatalf("目的地址期望 %s:%d, 实际 %s:%d", a.DstIP, a.DstPort, b.DstIP, b.DstPort)
	}
	if b.Proto != a.Proto {
		t.Fatalf("Proto 期望 %q, 实际 %q", a.Proto, b.Proto)
	}
	if b.StreamID != a.StreamID {
		t.Fatalf("StreamID 期望 %d, 实际 %d", a.StreamID, b.StreamID)
	}
	if b.PktNo != a.PktNo {
		t.Fatalf("PktNo 期望 %d, 实际 %d", a.PktNo, b.PktNo)
	}
	if b.FlowKey != a.FlowKey {
		t.Fatalf("FlowKey 期望 %q, 实际 %q", a.FlowKey, b.FlowKey)
	}
	if b.Buffer != a.Buffer {
		t.Fatalf("Buffer 期望 %q, 实际 %q", a.Buffer, b.Buffer)
	}
	if b.Offset != a.Offset {
		t.Fatalf("Offset 期望 %d, 实际 %d", a.Offset, b.Offset)
	}
	if b.Snippet != a.Snippet {
		t.Fatalf("Snippet 期望 %q, 实际 %q", a.Snippet, b.Snippet)
	}
}

// TestEventCarriesRunIDMode 回填链路要求 Event 保留 run_id / mode：
// 从 capture 发布的扁平 detect.feature 载荷经 decodeEvent 后必须带上它们。
func TestTask18bEventCarriesRunIDMode(t *testing.T) {
	payload := []byte(`{"capture_id":"capture.pcapng","run_id":"run-2024","mode":"live",` +
		`"rule_id":"r1","name":"命中","severity":"high","weight":7,` +
		`"time":"2024-01-02T03:04:05Z","src_ip":"10.0.0.5","src_port":50000,` +
		`"dst_ip":"93.184.216.34","dst_port":80,"proto":"HTTP","stream_id":3}`)

	ev, ok := decodeEvent(payload)
	if !ok {
		t.Fatal("decodeEvent 失败")
	}
	if ev.RunID != "run-2024" {
		t.Errorf("Event.RunID = %q, want run-2024", ev.RunID)
	}
	if ev.Mode != "live" {
		t.Errorf("Event.Mode = %q, want live", ev.Mode)
	}
	if ev.CaptureID != "capture.pcapng" {
		t.Errorf("Event.CaptureID = %q, want capture.pcapng", ev.CaptureID)
	}
	if ev.Alert.RuleID != "r1" {
		t.Errorf("Event.Alert.RuleID = %q, want r1", ev.Alert.RuleID)
	}
}

// TestEventJSONRoundTripRunIDMode 断言归档 JSON 往返保留 run_id / mode（omitempty 不丢值）。
func TestTask18bEventJSONRoundTripRunIDMode(t *testing.T) {
	src := Event{
		CaptureID: "cap",
		RunID:     "run-1",
		Mode:      "static",
		Alert:     detect.Alert{RuleID: "r1", Time: time.Unix(1700000000, 0).UTC()},
	}
	raw, err := json.Marshal(src)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var dst Event
	if err := json.Unmarshal(raw, &dst); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if dst.RunID != src.RunID || dst.Mode != src.Mode {
		t.Fatalf("run_id/mode 往返丢失: got %q/%q, want %q/%q",
			dst.RunID, dst.Mode, src.RunID, src.Mode)
	}
}
