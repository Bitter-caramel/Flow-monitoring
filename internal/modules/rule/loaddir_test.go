package rule

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRuleFile 在 dir 下创建 rel 文件并写入规则文本。
func writeRuleFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestLoadDirSources 验证三个来源目录各一条规则，Source 按目录正确填充。
func TestLoadDirSources(t *testing.T) {
	root := t.TempDir()
	writeRuleFile(t, root, "local/c.rules", `alert tcp any any -> any any (msg:"c"; content:"c"; sid:1000001;)`)
	writeRuleFile(t, root, "et/s.rules", `alert tcp any any -> any any (msg:"s"; content:"s"; sid:2000001;)`)
	writeRuleFile(t, root, "public/p.rules", `alert tcp any any -> any any (msg:"p"; content:"p"; sid:9000001;)`)

	rules, issues, err := LoadDir(root)
	if err != nil {
		t.Fatalf("LoadDir 返回错误: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("LoadDir issues = %v，期望空", issues)
	}
	if len(rules) != 3 {
		t.Fatalf("规则数 = %d，期望 3", len(rules))
	}

	want := map[string]Source{
		"1000001": SourceCustom,
		"2000001": SourceSuricata,
		"9000001": SourcePublic,
	}
	for _, r := range rules {
		src, ok := want[r.SourceID]
		if !ok {
			t.Errorf("出现未预期 sid %q", r.SourceID)
			continue
		}
		if r.Source != src {
			t.Errorf("sid %s 的 Source = %q，期望 %q", r.SourceID, r.Source, src)
		}
		if !strings.HasPrefix(r.ID, "suricata-") {
			t.Errorf("sid %s 的 ID = %q，期望保持 suricata- 前缀", r.SourceID, r.ID)
		}
	}
}

// TestLoadDirDuplicateSID 验证同 sid 出现在两个文件时产生 LoadIssue。
func TestLoadDirDuplicateSID(t *testing.T) {
	root := t.TempDir()
	writeRuleFile(t, root, "et/a.rules", `alert tcp any any -> any any (msg:"a"; content:"a"; sid:2000002;)`)
	writeRuleFile(t, root, "et/b.rules", `alert tcp any any -> any any (msg:"b"; content:"b"; sid:2000002;)`)

	rules, issues, err := LoadDir(root)
	if err != nil {
		t.Fatalf("LoadDir 返回错误: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("规则数 = %d，期望 1（重复的 sid 只保留首条）", len(rules))
	}
	if len(issues) != 1 {
		t.Fatalf("issues = %v，期望 1 条重复问题", issues)
	}
	if !strings.Contains(issues[0].Reason, "重复") || !strings.Contains(issues[0].Reason, "2000002") {
		t.Errorf("重复问题 = %+v，期望含“重复”与 sid", issues[0])
	}
}

// TestLoadDirOutOfRange 验证 custom 目录里的越界 sid 产生 LoadIssue 且不计入结果。
func TestLoadDirOutOfRange(t *testing.T) {
	root := t.TempDir()
	writeRuleFile(t, root, "local/bad.rules", `alert tcp any any -> any any (msg:"bad"; content:"x"; sid:2000001;)`)

	rules, issues, err := LoadDir(root)
	if err != nil {
		t.Fatalf("LoadDir 返回错误: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("规则数 = %d，期望 0（越界规则不应计入）", len(rules))
	}
	if len(issues) != 1 {
		t.Fatalf("issues = %v，期望 1 条越界问题", issues)
	}
	msg := issues[0].Reason
	if !strings.Contains(msg, "custom") || !strings.Contains(msg, "2000001") {
		t.Errorf("越界问题 = %q，期望含来源名与 sid", msg)
	}
}

// TestLoadDirUnknownDir 验证未知子目录产生 LoadIssue（即使目录为空也要报）。
func TestLoadDirUnknownDir(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "misc"), 0o755); err != nil {
		t.Fatalf("mkdir misc: %v", err)
	}
	writeRuleFile(t, root, "misc/x.rules", `alert tcp any any -> any any (msg:"x"; content:"x"; sid:1;)`)

	rules, issues, err := LoadDir(root)
	if err != nil {
		t.Fatalf("LoadDir 返回错误: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("规则数 = %d，期望 0", len(rules))
	}
	if len(issues) != 1 {
		t.Fatalf("issues = %v，期望 1 条未知目录问题", issues)
	}
	if !strings.Contains(issues[0].Reason, "未知来源目录") {
		t.Errorf("未知目录问题 = %+v，期望含“未知来源目录”", issues[0])
	}
}

// TestLoadDirMissingRoot 验证根目录不存在时返回 error。
func TestLoadDirMissingRoot(t *testing.T) {
	if _, _, err := LoadDir(filepath.Join(t.TempDir(), "no_such_dir")); err == nil {
		t.Fatal("LoadDir 不存在的根目录应返回 error，实际 nil")
	}
}
