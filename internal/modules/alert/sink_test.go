package alert

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"flow-monitoring/internal/modules/detect"
	"flow-monitoring/internal/modules/rule"
)

// evFor 造一条可 JSON 往返的测试告警；相同 (ruleID, streamID) 即为"同键"。
func evFor(ruleID string, streamID int, snippet string) Event {
	return Event{
		CaptureID: "cap-" + snippet,
		Alert: detect.Alert{
			RuleID:   ruleID,
			Name:     "规则 " + ruleID,
			Severity: "high",
			Weight:   5,
			Time:     time.Unix(1700000000, 0).UTC(),
			SrcIP:    "10.0.0.1",
			SrcPort:  1234,
			DstIP:    "10.0.0.2",
			DstPort:  80,
			Proto:    "HTTP",
			StreamID: streamID,
			PktNo:    1,
			FlowKey:  "10.0.0.1:1234->10.0.0.2:80/HTTP",
			Buffer:   rule.BufPayload,
			Offset:   0,
			Snippet:  snippet,
		},
	}
}

// eventsEqual 逐字段比较两条告警；时间用 Equal（避开时区/单调钟的表示差异）。
func eventsEqual(a, b Event) bool {
	if a.CaptureID != b.CaptureID {
		return false
	}
	x, y := a.Alert, b.Alert
	return x.RuleID == y.RuleID &&
		x.Name == y.Name &&
		x.Severity == y.Severity &&
		x.Weight == y.Weight &&
		x.Time.Equal(y.Time) &&
		x.SrcIP == y.SrcIP && x.SrcPort == y.SrcPort &&
		x.DstIP == y.DstIP && x.DstPort == y.DstPort &&
		x.Proto == y.Proto &&
		x.StreamID == y.StreamID &&
		x.PktNo == y.PktNo &&
		x.FlowKey == y.FlowKey &&
		x.Buffer == y.Buffer &&
		x.Offset == y.Offset &&
		x.Snippet == y.Snippet
}

// splitLines 把 JSON Lines 文本切成非空行。
func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// TestFileSinkJSONLines 守住 FileSink 的 JSON Lines 格式：一行一条、无数组包装/无 BOM，
// 每条可 JSON 往返，且 Close 后行数不变。
func TestFileSinkJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink 失败: %v", err)
	}

	want := []Event{
		evFor("r1", 1, "/a"),
		evFor("r1", 2, "/b"),
		evFor("r2", 1, "/c"),
	}
	for i, ev := range want {
		if err := sink.Write(ev); err != nil {
			t.Fatalf("第 %d 条 Write 失败: %v", i, err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	if err := sink.Close(); err != nil { // 幂等
		t.Fatalf("重复 Close 失败: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile 失败: %v", err)
	}
	if strings.HasPrefix(string(raw), "\xef\xbb\xbf") {
		t.Fatalf("文件不应有 BOM")
	}
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
		t.Fatalf("不应是数组包装, 实际开头: %q", strings.TrimSpace(string(raw))[:1])
	}

	lines := splitLines(string(raw))
	if len(lines) != 3 {
		t.Fatalf("期望恰好 3 行, 实际 %d 行", len(lines))
	}
	for i, line := range lines {
		var got Event
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("第 %d 行不是合法 JSON: %v", i, err)
		}
		if !eventsEqual(got, want[i]) {
			t.Fatalf("第 %d 行往返不相等:\n got=%+v\nwant=%+v", i, got, want[i])
		}
	}
}
