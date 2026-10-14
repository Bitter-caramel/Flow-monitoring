package hotpath

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"flow-monitoring/internal/modules/detect"
	"flow-monitoring/internal/modules/parse/decoder"
	"flow-monitoring/internal/modules/parse/pcapng"
	"flow-monitoring/internal/modules/rule"
)

// update：golden 写回开关；不带 -update 时只比对、绝不写文件。
var update = flag.Bool("update", false, "更新 golden 快照")

// goldenHit 一条命中 + 其 golden 行 + 是否来自 IPv6 包（仅计数，不进 golden）。
type goldenHit struct {
	line string
	buf  rule.Buffer
	ipv6 bool
}

// TestGoldenHits 引擎级 golden：规则集 + test.pcapng 经生产真路径 hotpath.Process 的命中行与 .golden 逐行比对。
// 三组锁：explicit-payload=10 命中全 payload；explicit-stream=13（含 IPv6）全 stream；default=裸规则命中>0 且 buf 一致。
// ★ default.golden 是 11-2「翻默认缓冲」信号线：11-2 落地时把旧文件另存为 default-v1-payload.golden 永久保留、
// 再 -update 生成新文件。default-v1-payload.golden 是 11-2 前的历史对照物（不参与比对），
// 11-2 后 default.golden 记录 stream 语义。行格式 No=<PktNo> sid=<RuleID> buf=<Buffer> off=<Offset> snip=<%q>，不含时间/绝对路径/耗时；
// golden 是生成物，只在人工确认变动合理后用 -update 更新。
func TestGoldenHits(t *testing.T) {
	cases := []struct {
		name, rules, golden string
		want                int
		buf                 rule.Buffer
	}{
		{"explicit-payload", "testdata/golden/explicit-payload.rules", "testdata/golden/explicit-payload.golden", 10, rule.BufPayload},
		{"explicit-stream", "testdata/golden/explicit-stream.rules", "testdata/golden/explicit-stream.golden", 13, rule.BufStream},
		{"default", "../modules/detect/testdata/e2e.rules", "testdata/golden/default.golden", 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := runGolden(t, tc.rules)
			checkMin(t, tc.name, hits, tc.want, tc.buf)
			checkGolden(t, tc.golden, hits)
		})
	}
}

// checkMin 三组最低期望断言（want>0 校验数量、buf!="" 校验每行缓冲；default 只要求一致）。
func checkMin(t *testing.T, name string, hits []goldenHit, want int, buf rule.Buffer) {
	ipv6 := 0
	for _, h := range hits {
		if h.ipv6 {
			ipv6++
		}
	}
	if len(hits) == 0 {
		t.Fatalf("%s 期望命中数 > 0", name)
	}
	if want > 0 && len(hits) != want {
		t.Errorf("%s 期望命中 %d，实际 %d", name, want, len(hits))
	}
	for i, h := range hits {
		if buf != "" && h.buf != buf {
			t.Errorf("%s 第 %d 行 buf=%s，期望 %s", name, i+1, h.buf, buf)
		}
		if buf == "" && h.buf != hits[0].buf {
			t.Errorf("%s 的所有命中 buf 必须一致：第 1 行 %s 第 %d 行 %s", name, hits[0].buf, i+1, h.buf)
		}
	}
	if name == "explicit-stream" {
		if ipv6 == 0 {
			t.Error("explicit-stream 期望至少 1 条命中来自 IPv6 包，实际 0")
		}
		t.Logf("explicit-stream: 来自 IPv6 包的 stream 命中 %d", ipv6)
	}
}

// runGolden 走生产真路径：LoadFile → New → 逐包 Decode → Process，产出规范化命中行。
func runGolden(t *testing.T, rulesPath string) []goldenHit {
	rs, err := detect.LoadFile(rulesPath)
	if err != nil {
		t.Fatalf("加载规则 %s 失败: %v", rulesPath, err)
	}
	hp := New(rs)
	defer hp.Close()
	data, err := os.ReadFile("../../testdata/test.pcapng")
	if err != nil {
		t.Fatalf("读取样本失败: %v", err)
	}
	cap, err := pcapng.Parse(data, 0)
	if err != nil {
		t.Fatalf("解析 pcapng 失败: %v", err)
	}
	var hits []goldenHit
	for _, p := range cap.Packets {
		if p == nil {
			continue
		}
		linkType := cap.LinkType
		if p.Iface >= 0 && p.Iface < len(cap.Ifaces) {
			linkType = cap.Ifaces[p.Iface].LinkType
		}
		decoder.Decode(p, linkType)
		for _, a := range hp.Process(p) {
			hits = append(hits, goldenHit{
				line: fmt.Sprintf("No=%d sid=%s buf=%s off=%d snip=%q", a.PktNo, a.RuleID, a.Buffer, a.Offset, a.Snippet),
				buf:  a.Buffer,
				ipv6: p.IPVersion == 6,
			})
		}
	}
	return hits
}

// checkGolden：带 -update 写回；否则读 golden 逐行比对（CRLF 归一化、忽略末尾空行差异）。
func checkGolden(t *testing.T, path string, hits []goldenHit) {
	got := make([]string, len(hits))
	for i, h := range hits {
		got[i] = h.line
	}
	if *update {
		if t.Failed() {
			t.Logf("最低期望断言未通过，跳过写回 %s（防止把 bug 烤进 golden）", path)
			return
		}
		if err := os.WriteFile(path, []byte(strings.Join(got, "\n")+"\n"), 0o644); err != nil {
			t.Fatalf("写回 golden 失败: %v", err)
		}
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 golden %s 失败（是否漏跑 -update？）: %v", path, err)
	}
	want := strings.Split(strings.TrimRight(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n"), "\n")
	get := func(s []string, i int) string {
		if i < len(s) {
			return s[i]
		}
		return "<缺失>"
	}
	for i := 0; i < len(want) || i < len(got); i++ {
		if w, g := get(want, i), get(got, i); w != g {
			t.Errorf("%s 第 %d 行不一致：\n  期望 %q\n  实际 %q", path, i+1, w, g)
		}
	}
}
