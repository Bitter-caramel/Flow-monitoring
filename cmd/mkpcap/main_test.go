package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"flow-monitoring/internal/modules/parse/pcapng"
)

// runCLI 调 run() 并收集退出码与两级输出（不碰 os.Exit / main）。
func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// expectedPackets 是每个场景应有的包数：normal 是 TCP + UDP 两个包，其余各一个。
var expectedPackets = map[string]int{
	"normal":    2,
	"sqli":      1,
	"traversal": 1,
	"dotgit":    1,
	"c2ua":      1,
	"dnstunnel": 1,
}

// TestScenariosRoundTrip 对每个场景生成到 t.TempDir()，再用 pcapng.Parse 读回，
// 断言包数与预期一致。
func TestScenariosRoundTrip(t *testing.T) {
	dir := t.TempDir()
	for _, name := range scenarioOrder {
		name := name
		t.Run(name, func(t *testing.T) {
			out := filepath.Join(dir, name+".pcapng")
			code, _, stderr := runCLI(t, "-scenario", name, "-out", out)
			if code != exitOK {
				t.Fatalf("退出码 = %d, 期望 %d; stderr=%s", code, exitOK, stderr)
			}

			data, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("读取生成文件: %v", err)
			}
			c, err := pcapng.Parse(data, 0)
			if err != nil {
				t.Fatalf("解析生成文件: %v", err)
			}
			if got, want := len(c.Packets), expectedPackets[name]; got != want {
				t.Fatalf("包数 = %d, 期望 %d", got, want)
			}
		})
	}
}

// TestDeterministic 同一场景生成两次，字节必须完全相同。
func TestDeterministic(t *testing.T) {
	for _, name := range scenarioOrder {
		name := name
		t.Run(name, func(t *testing.T) {
			first, firstPackets, err := generate(name, 0)
			if err != nil {
				t.Fatalf("第一次生成: %v", err)
			}
			second, secondPackets, err := generate(name, 0)
			if err != nil {
				t.Fatalf("第二次生成: %v", err)
			}
			if firstPackets != secondPackets {
				t.Fatalf("包数不稳定: %d vs %d", firstPackets, secondPackets)
			}
			if !bytes.Equal(first, second) {
				t.Fatalf("两次生成字节不一致（长度 %d vs %d）", len(first), len(second))
			}
		})
	}
}

// TestUsageErrors 未知 scenario / 缺 -out 必须以退出码 2 结束。
func TestUsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"unknown-scenario", []string{"-scenario", "bogus", "-out", filepath.Join(t.TempDir(), "x.pcapng")}},
		{"missing-out", []string{"-scenario", "sqli"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, tc.args...)
			if code != exitUsage {
				t.Fatalf("退出码 = %d, 期望 %d; stderr=%s", code, exitUsage, stderr)
			}
		})
	}
}

// TestAllMode -scenario all 应在目录下生成全部场景文件。
func TestAllMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attacks")
	code, stdout, stderr := runCLI(t, "-scenario", "all", "-out", dir)
	if code != exitOK {
		t.Fatalf("退出码 = %d, 期望 %d; stderr=%s", code, exitOK, stderr)
	}
	for _, name := range scenarioOrder {
		path := filepath.Join(dir, name+".pcapng")
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("缺少生成文件 %s: %v\nstdout=%s", path, err, stdout)
		}
	}
}

// TestHelp -h/--help 应打印用法并以 0 退出。
func TestHelp(t *testing.T) {
	for _, flagArg := range []string{"-h", "--help"} {
		code, stdout, _ := runCLI(t, flagArg)
		if code != exitOK {
			t.Fatalf("%s 退出码 = %d, 期望 %d", flagArg, code, exitOK)
		}
		if !strings.Contains(stdout, "用法:") {
			t.Fatalf("%s 未打印用法:\n%s", flagArg, stdout)
		}
	}
}
