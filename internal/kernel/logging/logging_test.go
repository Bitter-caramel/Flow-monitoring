package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestNew_SeqIncrement 验证每条日志带递增 seq。
func TestNew_SeqIncrement(t *testing.T) {
	var buf bytes.Buffer
	logger := New(LevelInfo, "json", &buf)
	logger.Info("first")
	logger.Info("second")
	logger.Info("third")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 log lines, got %d: %s", len(lines), buf.String())
	}
	wantSeqs := []uint64{1, 2, 3}
	for i, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d not json: %v", i, err)
		}
		got, _ := rec["seq"].(float64)
		if uint64(got) != wantSeqs[i] {
			t.Errorf("line %d seq: want %d, got %v", i, wantSeqs[i], got)
		}
	}
}

// TestNew_WithAttrs_SharesSeq 验证派生 logger 与父 logger 共享同一 seq 计数器。
func TestNew_WithAttrs_SharesSeq(t *testing.T) {
	var buf bytes.Buffer
	logger := New(LevelInfo, "json", &buf)
	child := logger.With("component", "test")
	logger.Info("parent1")
	child.Info("child1")
	logger.Info("parent2")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d", len(lines))
	}
	// parent1=1, child1=2, parent2=3
	wantSeqs := []uint64{1, 2, 3}
	for i, line := range lines {
		var rec map[string]any
		_ = json.Unmarshal([]byte(line), &rec)
		got, _ := rec["seq"].(float64)
		if uint64(got) != wantSeqs[i] {
			t.Errorf("line %d seq: want %d, got %v", i, wantSeqs[i], got)
		}
	}
}

// TestParseLevel 校验级别字符串解析。
func TestParseLevel(t *testing.T) {
	cases := map[string]Level{
		"DEBUG":  LevelDebug,
		"debug":  LevelDebug,
		"INFO":   LevelInfo,
		"":       LevelInfo,
		"unknown": LevelInfo,
		"WARN":   LevelWarn,
		"ERROR":  LevelError,
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestNew_BelowLevelFiltered 验证低于 level 的日志被过滤。
func TestNew_BelowLevelFiltered(t *testing.T) {
	var buf bytes.Buffer
	logger := New(LevelWarn, "json", &buf)
	logger.Info("should not appear")
	logger.Warn("should appear")

	if strings.Contains(buf.String(), "should not appear") {
		t.Errorf("INFO should be filtered at WARN level, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "should appear") {
		t.Errorf("WARN should appear, got: %s", buf.String())
	}
	// 确保 seq 仍然只递增"实际写入"的记录
	if !strings.Contains(buf.String(), `"seq":1`) {
		t.Errorf("seq should be 1 for first emitted log, got: %s", buf.String())
	}
}

