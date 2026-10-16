package main

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
)

// guardCountRE 匹配守卫输出里的"检查宿主闭包 <N> 个包"。
var guardCountRE = regexp.MustCompile(`检查宿主闭包\s+\d+\s+个包`)

// runCLI 调 run() 并收集退出码与两级输出（不碰 os.Exit / main）。
func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// listRows 取 --list 输出里以 "modules." 开头的模块行。
func listRows(out string) []string {
	var rows []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "modules.") {
			rows = append(rows, line)
		}
	}
	return rows
}

// findRow 按首列 ID 找一行。
func findRow(rows []string, id string) (string, bool) {
	for _, r := range rows {
		f := strings.Fields(r)
		if len(f) > 0 && f[0] == id {
			return r, true
		}
	}
	return "", false
}

// 测试 10：--list 全量输出 13 个模块，importer/query 两行是 build。
func TestRun_List_AllModules(t *testing.T) {
	code, stdout, stderr := runCLI(t, "--repo=../..", "--list")
	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr)
	}
	rows := listRows(stdout)
	if len(rows) != 13 {
		t.Fatalf("模块行数 = %d, want 13\n%s", len(rows), stdout)
	}
	for _, id := range []string{"modules.importer", "modules.query"} {
		row, ok := findRow(rows, id)
		if !ok {
			t.Fatalf("未找到 %s 行\n%s", id, stdout)
		}
		if !strings.Contains(row, "build") {
			t.Errorf("%s 行 = %q, want 含 build", id, row)
		}
	}
}

// 测试 11：--list --modules=disposal 的两跳闭包 = disposal+situation+detect。
func TestRun_List_ModulesClosure(t *testing.T) {
	code, stdout, stderr := runCLI(t, "--repo=../..", "--list", "--modules=disposal")
	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr)
	}
	rows := listRows(stdout)
	for _, id := range []string{"modules.disposal", "modules.situation", "modules.detect"} {
		if _, ok := findRow(rows, id); !ok {
			t.Errorf("未找到闭包成员 %s\n%s", id, stdout)
		}
	}
}

// 测试 12：用法/选择错误一律退出码 2。
func TestRun_UsageErrorsExit2(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"unknown-module", []string{"--repo=../..", "--modules=nope"}},
		{"all-with-core-only", []string{"--repo=../..", "--all", "--core-only"}},
		{"duplicate-modules", []string{"--repo=../..", "--modules=query", "--modules=importer"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, tc.args...)
			if code != 2 {
				t.Errorf("run(%v) = %d, want 2; stderr=%s", tc.args, code, stderr)
			}
		})
	}
}

// 测试 13：--list 不产生任何文件。
func TestRun_ListWritesNothing(t *testing.T) {
	out := t.TempDir()
	code, _, stderr := runCLI(t, "--repo=../..", "--list", "--out="+out)
	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", out, err)
	}
	if len(entries) != 0 {
		t.Errorf("out 目录非空: %v", entries)
	}
}

// 测试 14：空注册表目录 ⇒ 退出码 2（空计划不当成功）。
func TestRun_EmptyRegistryExit2(t *testing.T) {
	regDir := t.TempDir()
	code, _, stderr := runCLI(t, "--repo=../..", "--registry="+regDir)
	if code != 2 {
		t.Errorf("code = %d, want 2; stderr=%s", code, stderr)
	}
}

// 测试 15：--guard-only 在真实仓库通过（退出码 0），并打印检查包数。
func TestRun_GuardOnly_RealRepo(t *testing.T) {
	code, stdout, stderr := runCLI(t, "--guard-only", "--repo=../..")
	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "检查宿主闭包") {
		t.Errorf("stdout 缺 '检查宿主闭包': %q", stdout)
	}
	if !guardCountRE.MatchString(stdout) {
		t.Errorf("stdout 缺检查包数: %q", stdout)
	}
	if !strings.Contains(stdout, "通过") {
		t.Errorf("stdout 缺 '通过': %q", stdout)
	}
}

// 测试 16：--list 不跑守卫（空目录、无 go.mod 仍返回 0，证明不依赖 go 工具链）。
func TestRun_ListDoesNotRunGuard(t *testing.T) {
	empty := t.TempDir()
	code, stdout, stderr := runCLI(t, "--list", "--repo="+empty)
	if code != 0 {
		t.Fatalf("code = %d, want 0; stdout=%s stderr=%s", code, stdout, stderr)
	}
}
