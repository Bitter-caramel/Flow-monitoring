package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// wantSIDsBySample 是任务 14-2b 的验收基线：每个样本「应当命中」的 sid 全集。
// 断言必须完全相等（不是"至少一个"），这样才能同时守住漏报与误报。
var wantSIDsBySample = map[string][]string{
	"normal":    nil,
	"sqli":      {"1000001", "1000002", "1000007"},
	"traversal": {"1000003", "2000001"}, // 自写规则 + 社区模拟规则同时生效
	"dotgit":    {"1000004"},
	"c2ua":      {"1000005"},
	"dnstunnel": {"1000006"},
}

// hitSIDPattern 提取命中行的 sid：`规则=suricata-1000001(...)`。
var hitSIDPattern = regexp.MustCompile(`规则=suricata-([0-9]+)`)

// attackSamplePath 返回样本路径。go test 的工作目录是 cmd/parse-cli，故向上两级。
func attackSamplePath(name string) string {
	return filepath.Join("..", "..", "testdata", "attacks", name+".pcapng")
}

// repoRulesDir 返回仓库根下的规则目录 rules/。
func repoRulesDir() string {
	return filepath.Join("..", "..", "rules")
}

// hitSIDsFromOutput 从 CLI 输出里收集命中的 sid（去重、升序）。
func hitSIDsFromOutput(stdout string) []string {
	set := make(map[string]struct{})
	for _, m := range hitSIDPattern.FindAllStringSubmatch(stdout, -1) {
		set[m[1]] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for sid := range set {
		out = append(out, sid)
	}
	sort.Strings(out)
	return out
}

// sameStringSlice 判断两个已排序切片是否完全相等。
func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestRulesDirHitsExactSIDSet 对 6 个样本逐一跑
// `parse-cli <sample> --rules-dir rules`，断言：
//  1. 命中 sid 集合与预期「完全相等」（既不许漏，也不许多）；
//  2. 导入报告真的打印且统计正确（8 条：custom 7 + suricata 1）；
//  3. normal 样本零告警。
func TestRulesDirHitsExactSIDSet(t *testing.T) {
	dir := repoRulesDir()
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("规则目录不可用 %s: %v", dir, err)
	}

	order := []string{"normal", "sqli", "traversal", "dotgit", "c2ua", "dnstunnel"}
	for _, name := range order {
		name := name
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runParseCLI(t, attackSamplePath(name), "--rules-dir", dir)
			if code != 0 {
				t.Fatalf("退出码 = %d, 期望 0; stderr=%s", code, stderr)
			}

			// 导入报告必须真的打印：总览 8 条，按来源 custom=7 / suricata=1。
			if !strings.Contains(stdout, "规则集导入报告") {
				t.Fatalf("stdout 未打印规则集导入报告:\n%s", stdout)
			}
			if !strings.Contains(stdout, "总览：共 8 条，成功编译 8 条，失败 0 条") {
				t.Fatalf("导入报告总览不符:\n%s", stdout)
			}
			if !strings.Contains(stdout, "custom: 7") || !strings.Contains(stdout, "suricata: 1") {
				t.Fatalf("导入报告来源统计不符:\n%s", stdout)
			}

			got := hitSIDsFromOutput(stdout)
			want := wantSIDsBySample[name]
			if !sameStringSlice(got, want) {
				t.Fatalf("命中 sid 集合 = %v, 期望完全相等 %v\nstdout:\n%s", got, want, stdout)
			}

			// normal 必须零告警（命中次数 0）。
			if name == "normal" && !strings.Contains(stdout, "=== 检测结果：命中 0 次，涉及 0 条规则 ===") {
				t.Fatalf("normal 未做到零告警:\n%s", stdout)
			}
		})
	}
}
