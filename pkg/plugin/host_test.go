package plugin

import "testing"

// TestConfigSnapshotSection 覆盖 Section 的三种情形：存在 / 不存在（含 Raw 为空）/ Raw 非法。
func TestConfigSnapshotSection(t *testing.T) {
	t.Run("exists", func(t *testing.T) {
		var out struct {
			SinkPath string `json:"sink_path"`
		}
		cfg := ConfigSnapshot{Raw: `{"alert":{"sink_path":"/tmp/a.jsonl"}}`}
		if err := cfg.Section("alert", &out); err != nil {
			t.Fatalf("Section 返回错误: %v", err)
		}
		if out.SinkPath != "/tmp/a.jsonl" {
			t.Fatalf("SinkPath = %q", out.SinkPath)
		}
	})

	t.Run("missing", func(t *testing.T) {
		var out struct {
			SinkPath string `json:"sink_path"`
		}
		cfg := ConfigSnapshot{Raw: `{"alert":{"sink_path":"/tmp/a.jsonl"}}`}
		if err := cfg.Section("detect", &out); err != nil {
			t.Fatalf("键不存在应返回 nil，实际: %v", err)
		}
		if out.SinkPath != "" {
			t.Fatalf("键不存在时 out 应保持零值，实际 %q", out.SinkPath)
		}
	})

	t.Run("empty_raw", func(t *testing.T) {
		var out map[string]string
		if err := (ConfigSnapshot{}).Section("alert", &out); err != nil {
			t.Fatalf("Raw 为空应返回 nil，实际: %v", err)
		}
		if out != nil {
			t.Fatalf("Raw 为空时 out 应保持零值，实际 %v", out)
		}
	})

	t.Run("invalid_json", func(t *testing.T) {
		var out map[string]string
		if err := (ConfigSnapshot{Raw: `not-json`}).Section("alert", &out); err == nil {
			t.Fatal("非法 Raw 应返回错误")
		}
	})

	t.Run("wrong_shape", func(t *testing.T) {
		var out string
		if err := (ConfigSnapshot{Raw: `{"alert":{}}`}).Section("alert", &out); err == nil {
			t.Fatal("类型不匹配应返回错误")
		}
	})
}
