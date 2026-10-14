package detect

import (
	"path/filepath"
	"strings"
	"testing"

	"flow-monitoring/internal/modules/rule"
)

// TestLoadFileBasicReport 验证 basic.rules 夹具的计数、词法错误、剔除与不支持项、备注、报告稳定性及引擎索引。
func TestLoadFileBasicReport(t *testing.T) {
	rs, err := LoadFile(filepath.Join("testdata", "basic.rules"))
	if err != nil {
		t.Fatalf("LoadFile 失败: %v", err)
	}
	rep := rs.Report

	// a) 确切计数：Total=7、Compiled=5、Failed=2。
	if rep.Total != 7 || rep.Compiled != 5 || rep.Failed != 2 {
		t.Fatalf("计数不符：Total=%d Compiled=%d Failed=%d，期望 7/5/2", rep.Total, rep.Compiled, rep.Failed)
	}

	// b) LexErrors 恰 2 条，顺序为 line 6（垃圾行）、line 7（sid 非法）。
	if len(rep.LexErrors) != 2 {
		t.Fatalf("LexErrors 应为 2 条，实际 %d：%v", len(rep.LexErrors), rep.LexErrors)
	}
	if !strings.HasPrefix(rep.LexErrors[0], "line 6:") {
		t.Errorf("第 1 条词法错误应为 line 6，实际 %q", rep.LexErrors[0])
	}
	if !strings.HasPrefix(rep.LexErrors[1], "line 7:") {
		t.Errorf("第 2 条词法错误应为 line 7，实际 %q", rep.LexErrors[1])
	}

	// c) DroppedRules 必须为空（真实文本造不出被剔除的规则）。
	if len(rep.DroppedRules) != 0 {
		t.Errorf("DroppedRules 应为空，实际 %v", rep.DroppedRules)
	}

	// d) Unsupported 恰 2 项，顺序为 "flowbits x1"、"http_stat_code x1"（同次数按字典序）。
	wantUnsupported := []string{"flowbits x1", "http_stat_code x1"}
	if len(rep.Unsupported) != len(wantUnsupported) {
		t.Fatalf("Unsupported 应为 %v，实际 %v", wantUnsupported, rep.Unsupported)
	}
	for i, want := range wantUnsupported {
		if rep.Unsupported[i] != want {
			t.Errorf("Unsupported[%d] 应为 %q，实际 %q", i, want, rep.Unsupported[i])
		}
	}

	// e) Notes 存在 key "suricata-100005"，其备注含 "flow 方向条件"。
	notes, ok := rep.Notes["suricata-100005"]
	if !ok {
		t.Fatalf("Notes 缺少 key suricata-100005，实际 %v", rep.Notes)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "flow 方向条件") {
		t.Errorf("suricata-100005 备注应含 \"flow 方向条件\"，实际 %v", notes)
	}

	// f) String() 非空、含"总览"、两次调用完全一致，且空段不打印。
	s1 := rep.String()
	s2 := rep.String()
	if s1 == "" {
		t.Fatal("Report.String() 不应为空")
	}
	if !strings.Contains(s1, "总览") {
		t.Errorf("Report.String() 应含 \"总览\"，实际:\n%s", s1)
	}
	if s1 != s2 {
		t.Errorf("Report.String() 两次调用应一致\n第一次:\n%s\n第二次:\n%s", s1, s2)
	}
	if strings.Contains(s1, "[编译失败]") {
		t.Errorf("编译失败段为空时不应打印，实际:\n%s", s1)
	}
	if strings.Contains(s1, "[被剔除的规则]") {
		t.Errorf("被剔除段为空时不应打印，实际:\n%s", s1)
	}

	// i) Engine() 非 nil 且 RuleCount()==5。
	eng := rs.Engine()
	if eng == nil {
		t.Fatal("Engine() 不应为 nil")
	}
	if got := eng.RuleCount(); got != 5 {
		t.Errorf("Engine().RuleCount() 应为 5，实际 %d", got)
	}
}

// TestLoadFileMissing 验证读取不存在的规则文件时返回 error。
func TestLoadFileMissing(t *testing.T) {
	if _, err := LoadFile(filepath.Join("testdata", "no_such_file.rules")); err == nil {
		t.Fatal("LoadFile 不存在的文件应返回 error，实际为 nil")
	}
}

// TestLoadTextEmpty 验证空文本导入：计数为 0、Programs 为空、Notes 非 nil，且报告非空、不 panic。
func TestLoadTextEmpty(t *testing.T) {
	rs := LoadText("")
	if rs.Report.Total != 0 {
		t.Errorf("空文本 Total 应为 0，实际 %d", rs.Report.Total)
	}
	if len(rs.Programs) != 0 {
		t.Errorf("空文本 Programs 应为空，实际 %v", rs.Programs)
	}
	if rs.Report.Notes == nil {
		t.Error("空文本 Notes 不应为 nil")
	}
	if s := rs.Report.String(); s == "" {
		t.Error("空文本 Report.String() 不应为空")
	}
}

// TestUsesBufferFile 验证从 e2e.rules 载入后 UsesBuffer 的判定：
// 这些规则默认用 payload，没有任何条件引用 stream。
func TestUsesBufferFile(t *testing.T) {
	rs, err := LoadFile(filepath.Join("testdata", "e2e.rules"))
	if err != nil {
		t.Fatalf("LoadFile 失败: %v", err)
	}
	if !rs.UsesBuffer(rule.BufPayload) {
		t.Error("UsesBuffer(rule.BufPayload) 应为 true")
	}
	if rs.UsesBuffer(rule.BufStream) {
		t.Error("UsesBuffer(rule.BufStream) 应为 false")
	}
}

// TestUsesBufferStreamInline 验证显式引用 stream 缓冲的内联规则能被识别。
func TestUsesBufferStreamInline(t *testing.T) {
	rs := LoadText(`alert tcp any any -> any any (msg:"x"; stream; content:"x"; sid:930001;)`)
	for _, p := range rs.Programs {
		for _, c := range p.Conds {
			t.Logf("cond kind=%s buf=%q", c.Kind, c.Buf)
		}
	}
	if !rs.UsesBuffer(rule.BufStream) {
		t.Errorf("UsesBuffer(rule.BufStream) 应为 true；报告:\n%s", rs.Report.String())
	}
}

// TestUsesBufferNil 验证 nil 接收者安全返回 false（上层在无规则集时不会 panic）。
func TestUsesBufferNil(t *testing.T) {
	var rs *RuleSet
	if rs.UsesBuffer(rule.BufStream) {
		t.Error("nil RuleSet 的 UsesBuffer 应返回 false")
	}
}

// TestCompileRulesDroppedBuffer 直接验证 compileRules 的"不支持缓冲区剔除"与"其它编译错误"两条分支。
func TestCompileRulesDroppedBuffer(t *testing.T) {
	// 引用引擎不支持的缓冲区 -> 应被剔除进 dropped。
	bad := &rule.CompiledRule{
		Rule: rule.Rule{ID: "fake-1"},
		Matchers: []rule.Matcher{{
			Kind:    rule.CondContent,
			Buffer:  rule.Buffer("no_such_buffer"),
			Content: "zz",
		}},
	}
	progs, dropped, compileErrs := compileRules([]*rule.CompiledRule{bad})
	if len(progs) != 0 {
		t.Errorf("被剔除的规则不应产出程序，实际 %d 条", len(progs))
	}
	if len(dropped) != 1 {
		t.Fatalf("dropped 应恰 1 条，实际 %v", dropped)
	}
	if !strings.Contains(dropped[0], "no_such_buffer") {
		t.Errorf("dropped 明细应含 no_such_buffer，实际 %q", dropped[0])
	}
	if len(compileErrs) != 0 {
		t.Errorf("被剔除不应计入 compileErrs，实际 %v", compileErrs)
	}

	// 无 matcher 的规则 -> 应进 compileErrs（其它错误路径）。
	noMatcher := &rule.CompiledRule{Rule: rule.Rule{ID: "fake-2"}}
	progs2, dropped2, compileErrs2 := compileRules([]*rule.CompiledRule{noMatcher})
	if len(progs2) != 0 || len(dropped2) != 0 {
		t.Errorf("无 matcher 规则不应产出程序或剔除明细，实际 progs=%d dropped=%v", len(progs2), dropped2)
	}
	if len(compileErrs2) != 1 {
		t.Fatalf("无 matcher 规则应计入 compileErrs 恰 1 条，实际 %v", compileErrs2)
	}
}
