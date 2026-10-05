package rule

import (
	"strings"
	"testing"
)

// ruleIDs 返回结果中所有已编译规则的 ID，便于断言存在性。
func ruleIDs(res *TranslateResult) []string {
	ids := make([]string, 0, len(res.Rules))
	for _, r := range res.Rules {
		ids = append(ids, r.ID)
	}
	return ids
}

// 验证 Translate 的统计口径：Total = 解析成功条数 + 失败条数。
// 本文本含 2 条合法规则、1 行垃圾、1 条 sid 非数字的规则，
// 实测 Total=4（2 成功 + 2 失败）、Compiled=2、Failed=2。
func TestTranslateStats(t *testing.T) {
	text := `alert tcp any any -> any any (msg:"good1"; content:"aaa"; sid:1001;)
alert tcp any any -> any any (msg:"good2"; content:"bbb"; sid:1002;)
this is a garbage line
alert tcp any any -> any any (msg:"badsid"; content:"ccc"; sid:abc;)`
	res := Translate(text)
	if res.Total != 4 {
		t.Errorf("Total: 期望 4, 实际 %d", res.Total)
	}
	if res.Compiled != 2 {
		t.Errorf("Compiled: 期望 2, 实际 %d (IDs=%v)", res.Compiled, ruleIDs(res))
	}
	if res.Failed != 2 {
		t.Errorf("Failed: 期望 2, 实际 %d", res.Failed)
	}
	if res.Total != res.Compiled+res.Failed {
		t.Errorf("Total 口径: 期望 Total(%d) == Compiled(%d) + Failed(%d), 实际不等",
			res.Total, res.Compiled, res.Failed)
	}
}

// 验证不支持项的汇总：未知关键字与不支持的 pcre 各自计数为 1。
func TestTranslateUnsupportedSummary(t *testing.T) {
	text := `alert tcp any any -> any any (msg:"u1"; unknownopt:xyz; sid:1;)
alert tcp any any -> any any (msg:"u2"; pcre:"/(?=x)y/"; content:"abc"; sid:2;)`
	res := Translate(text)
	if got := res.Unsupported["unknownopt"]; got != 1 {
		t.Errorf("Unsupported[unknownopt]: 期望 1, 实际 %d (map=%v)", got, res.Unsupported)
	}
	found := false
	for k, v := range res.Unsupported {
		if strings.HasPrefix(k, "pcre 不支持: ") && v == 1 {
			found = true
		}
	}
	if !found {
		t.Errorf("Unsupported 中 pcre 不支持键: 期望存在且计数为 1, 实际 %v", res.Unsupported)
	}
}

// 验证错误隔离：坏行不影响好行被编译，且好规则的 ID 出现在结果里。
func TestTranslateErrorIsolation(t *testing.T) {
	text := `garbage line here
alert tcp any any -> any any (msg:"good"; content:"aaa"; sid:1001;)`
	res := Translate(text)
	if len(res.Rules) != 1 {
		t.Fatalf("已编译规则数: 期望 1, 实际 %d (IDs=%v)", len(res.Rules), ruleIDs(res))
	}
	if res.Rules[0].ID != "suricata-1001" {
		t.Errorf("好规则 ID: 期望 %q, 实际 %q", "suricata-1001", res.Rules[0].ID)
	}
}

// 验证空输入的统计为 0 且四个集合均非 nil。
func TestTranslateEmpty(t *testing.T) {
	res := Translate("")
	if res.Total != 0 || res.Compiled != 0 || res.Failed != 0 {
		t.Errorf("空输入统计: 期望 0/0/0, 实际 %d/%d/%d", res.Total, res.Compiled, res.Failed)
	}
	if res.Rules == nil {
		t.Errorf("Rules: 期望非 nil, 实际 nil")
	}
	if res.LexErrors == nil {
		t.Errorf("LexErrors: 期望非 nil, 实际 nil")
	}
	if res.CompileErrs == nil {
		t.Errorf("CompileErrs: 期望非 nil, 实际 nil")
	}
	if res.Unsupported == nil {
		t.Errorf("Unsupported: 期望非 nil, 实际 nil")
	}
}
