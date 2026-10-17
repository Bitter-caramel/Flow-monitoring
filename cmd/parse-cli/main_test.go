package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runParseCLI 调 run() 并收集退出码与两级输出（不碰 os.Exit / main）。
func runParseCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// TestRulesDirDetectMutualExclusion 验证 --detect 与 --rules-dir 同时给出时
// 一律以退出码 2 结束，并在 stderr 打印二选一提示。
// 覆盖三种参数顺序/组合，尤其是「没给文件名」这一种：
// 互斥是纯参数层面的用法错误，不能因为缺文件名就先报别的错。
func TestRulesDirDetectMutualExclusion(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{
			name: "文件在前",
			args: []string{"whatever.pcapng", "--detect", "a.rules", "--rules-dir", "rules"},
		},
		{
			name: "标志在前",
			args: []string{"--detect", "a.rules", "--rules-dir", "rules", "whatever.pcapng"},
		},
		{
			name: "缺文件名",
			args: []string{"--detect", "a.rules", "--rules-dir", "rules"},
		},
		{
			name: "等号写法",
			args: []string{"whatever.pcapng", "--detect=a.rules", "--rules-dir=rules"},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runParseCLI(t, tc.args...)
			if code != 2 {
				t.Fatalf("退出码 = %d, 期望 2; stderr=%s", code, stderr)
			}
			if !strings.Contains(stderr, "--detect") || !strings.Contains(stderr, "--rules-dir") {
				t.Fatalf("stderr 未包含互斥提示: %q", stderr)
			}
		})
	}
}

// TestNoFileArgument 验证缺少文件名时以退出码 1 结束并打印用法。
func TestNoFileArgument(t *testing.T) {
	code, _, stderr := runParseCLI(t)
	if code != 1 {
		t.Fatalf("退出码 = %d, 期望 1; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "用法") {
		t.Fatalf("stderr 未包含用法提示: %q", stderr)
	}
}

// TestDetectSingleFileStillWorks 是 --detect 路径的回归守卫：
// 引入 --rules-dir 后，单文件加载的行为（打印报告 + 命中）必须保持不变。
func TestDetectSingleFileStillWorks(t *testing.T) {
	rulePath := filepath.Join("..", "..", "rules", "local", "sqli.rules")
	if _, err := os.Stat(rulePath); err != nil {
		t.Fatalf("规则文件不可用 %s: %v", rulePath, err)
	}
	code, stdout, stderr := runParseCLI(t, filepath.Join("..", "..", "testdata", "attacks", "sqli.pcapng"), "--detect", rulePath)
	if code != 0 {
		t.Fatalf("退出码 = %d, 期望 0; stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "规则集导入报告") {
		t.Fatalf("--detect 未打印导入报告:\n%s", stdout)
	}
	if !strings.Contains(stdout, "规则=suricata-1000001") {
		t.Fatalf("--detect 未命中 sid 1000001:\n%s", stdout)
	}
}
