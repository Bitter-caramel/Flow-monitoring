package rule

import (
	"strings"
	"testing"
	"time"
)

// TestExportSourceDeterministic 验证导出文本的头信息、文件顺序与可复现性。
func TestExportSourceDeterministic(t *testing.T) {
	old := exportNow
	defer func() { exportNow = old }()
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	exportNow = func() time.Time { return fixed }

	root := t.TempDir()
	// 故意先写 b 再写 a，验证导出按文件名升序而不是写入顺序。
	writeRuleFile(t, root, "local/b.rules", `alert tcp any any -> any any (msg:"b"; content:"b"; sid:1000002;)`)
	writeRuleFile(t, root, "local/a.rules", `alert tcp any any -> any any (msg:"a"; content:"a"; sid:1000001;)`)

	got1, err := ExportSource(root, SourceCustom)
	if err != nil {
		t.Fatalf("ExportSource 返回错误: %v", err)
	}
	got2, err := ExportSource(root, SourceCustom)
	if err != nil {
		t.Fatalf("ExportSource 第二次返回错误: %v", err)
	}
	if got1 != got2 {
		t.Errorf("同一固定时间下两次导出应完全一致\n第一次:\n%s\n第二次:\n%s", got1, got2)
	}

	for _, want := range []string{
		"# source: custom",
		"# count: 2",
		"# generated: 2026-01-02T03:04:05Z",
	} {
		if !strings.Contains(got1, want) {
			t.Errorf("导出文本缺少 %q，实际:\n%s", want, got1)
		}
	}

	ia := strings.Index(got1, `msg:"a"`)
	ib := strings.Index(got1, `msg:"b"`)
	if ia < 0 || ib < 0 || ia > ib {
		t.Errorf("文件顺序应按文件名升序（a.rules 在 b.rules 前）；a=%d b=%d\n%s", ia, ib, got1)
	}
}

// TestExportSourceUnknownSource 验证未知来源返回 error。
func TestExportSourceUnknownSource(t *testing.T) {
	if _, err := ExportSource(t.TempDir(), Source("no_such_source")); err == nil {
		t.Fatal("未知来源应返回 error，实际 nil")
	}
}
