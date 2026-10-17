package rule_test

import (
	"os"
	"path/filepath"
	"testing"

	"flow-monitoring/internal/modules/rule"
	"flow-monitoring/internal/modules/rule/pipeline"
)

// TestExportSourceRoundTrip 验证导出文本再喂给 TranslateSource 能编译出相同条数。
func TestExportSourceRoundTrip(t *testing.T) {
	root := t.TempDir()
	local := filepath.Join(root, "local")
	if err := os.MkdirAll(local, 0o755); err != nil {
		t.Fatalf("mkdir local: %v", err)
	}
	files := map[string]string{
		"a.rules": `alert tcp any any -> any any (msg:"a"; content:"abc"; sid:1000001;)`,
		"b.rules": `alert udp any any -> any 53 (msg:"b"; dns_query; content:"evil"; sid:1000002;)`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(local, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	text, err := rule.ExportSource(root, rule.SourceCustom)
	if err != nil {
		t.Fatalf("ExportSource 返回错误: %v", err)
	}

	res := pipeline.TranslateSource(text, rule.SourceCustom)
	if res.Compiled != len(files) {
		t.Fatalf("往返后编译条数 = %d，期望 %d\n导出文本:\n%s\n错误: %v", res.Compiled, len(files), text, res.CompileErrs)
	}
	for _, r := range res.Rules {
		if r.Source != rule.SourceCustom {
			t.Errorf("往返后规则 %q 的 Source = %q，期望 %q", r.ID, r.Source, rule.SourceCustom)
		}
	}
}
