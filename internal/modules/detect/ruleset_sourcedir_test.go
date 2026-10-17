package detect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRule 在 root/sub 下写一个规则文件，目录不存在则创建。
func writeRule(t *testing.T, root, sub, name, body string) {
	t.Helper()
	dir := filepath.Join(root, sub)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// TestLoadDirBySource 验证 detect.LoadDir 的核心承诺：
//  1. 来源由所在目录决定（local→custom / et→suricata / public→public）；
//  2. BySource 按来源分别计数，而不是全部算成 suricata；
//  3. 报告渲染稳定、含 [按来源统计] 段。
//
// ★ 为什么必须有这条：如果 TranslateSource 没有真正覆盖 Source，
// 这里会看到 BySource 只有一个 key（suricata），这正是「能同时兼容社区与自写规则」
// 在实现上是否成立的分界线。
func TestLoadDirBySource(t *testing.T) {
	root := t.TempDir()
	writeRule(t, root, "local", "a.rules",
		`alert tcp any any -> any any (msg:"local-rule"; content:"LOCALHIT"; sid:1000001;)`)
	writeRule(t, root, "et", "b.rules",
		`alert tcp any any -> any any (msg:"et-rule"; content:"ETHIT"; sid:2000001;)`)
	writeRule(t, root, "public", "c.rules",
		`alert tcp any any -> any any (msg:"public-rule"; content:"PUBHIT"; sid:9000001;)`)

	rs, rep := LoadDir(root)
	if rs == nil || rep == nil {
		t.Fatal("LoadDir 返回 nil")
	}
	if rep.Compiled != 3 {
		t.Fatalf("Compiled = %d, want 3; issues=%v", rep.Compiled, rep.Issues)
	}
	want := map[string]int{"custom": 1, "suricata": 1, "public": 1}
	for k, v := range want {
		if got := rep.BySource[k]; got != v {
			t.Errorf("BySource[%q] = %d, want %d (全部: %v)", k, got, v, rep.BySource)
		}
	}
	if len(rep.Issues) != 0 {
		t.Errorf("正常目录不应有问题，实际 Issues = %v", rep.Issues)
	}

	s1, s2 := rep.String(), rep.String()
	if s1 != s2 {
		t.Error("报告输出不稳定：连调两次结果不同")
	}
	if !strings.Contains(s1, "[按来源统计]") {
		t.Errorf("报告缺 [按来源统计] 段:\n%s", s1)
	}
	for _, kv := range []string{"custom: 1", "suricata: 1", "public: 1"} {
		if !strings.Contains(s1, kv) {
			t.Errorf("报告缺 %q:\n%s", kv, s1)
		}
	}
}

// TestLoadDirIssues 验证问题必须被报告而不是静默吞掉，且越界/重复的规则不进结果：
//   - 越界：local（custom 段）里写 suricata 段位的 sid；
//   - 重复：同一来源目录内两条同 sid（★ 必须在同一号段内，否则先被"越界"拦下，
//     根本走不到重复分支——第一版测试就栽在这里）；
//   - 未知来源目录：只报一条"未知来源目录"，其下文件不参与校验。
func TestLoadDirIssues(t *testing.T) {
	root := t.TempDir()
	// 越界
	writeRule(t, root, "local", "oor.rules",
		`alert tcp any any -> any any (msg:"oor"; content:"OOR"; sid:2000002;)`)
	// 重复（同段位 2xxxxxx，都在 et 目录）
	writeRule(t, root, "et", "dup1.rules",
		`alert tcp any any -> any any (msg:"dup1"; content:"DUP"; sid:2000003;)`)
	writeRule(t, root, "et", "dup2.rules",
		`alert tcp any any -> any any (msg:"dup2"; content:"DUP2"; sid:2000003;)`)
	// 未知来源目录
	writeRule(t, root, "misc", "x.rules",
		`alert tcp any any -> any any (msg:"misc"; content:"MISC"; sid:1000009;)`)

	rs, rep := LoadDir(root)
	if rep == nil {
		t.Fatal("LoadDir 返回 nil report")
	}
	joined := strings.Join(rep.Issues, "\n")
	if len(rep.Issues) == 0 {
		t.Fatal("越界/重复/未知目录三类问题都未被报告（Issues 为空）")
	}
	// 越界：必须指出来源与区间
	if !strings.Contains(joined, "2000002") || !strings.Contains(joined, "custom") {
		t.Errorf("未报告 sid 2000002 在 custom 段越界:\n%s", joined)
	}
	// 重复：必须指出 sid 重复
	if !strings.Contains(joined, "2000003") || !strings.Contains(joined, "重复") {
		t.Errorf("未报告 sid 2000003 重复:\n%s", joined)
	}
	// 未知目录
	if !strings.Contains(joined, "misc") {
		t.Errorf("未报告未知来源目录 misc:\n%s", joined)
	}
	// 结果只剩 dup1 这一条（越界的 oor 与重复的 dup2 都不进结果；misc 下文件被跳过）
	if rs == nil || len(rs.Programs) != 1 {
		got := -1
		if rs != nil {
			got = len(rs.Programs)
		}
		t.Errorf("Programs 条数 = %d, want 1（只有 et/dup1 合法）", got)
	}
	if !strings.Contains(rep.String(), "[加载问题]") {
		t.Errorf("报告缺 [加载问题] 段:\n%s", rep.String())
	}
}
