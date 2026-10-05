package suricata

import (
	"strings"
	"testing"
)

// optIndexOf 返回键 name 在选项列表中首次出现的下标，未找到返回 -1。
func optIndexOf(opts []Option, name string) int {
	for i, o := range opts {
		if o.Key == name {
			return i
		}
	}
	return -1
}

// optVal 返回键 name 对应的值以及是否找到。
func optVal(opts []Option, name string) (string, bool) {
	for _, o := range opts {
		if o.Key == name {
			return o.Value, true
		}
	}
	return "", false
}

// optKeys 依次返回所有选项的键，便于断言顺序。
func optKeys(opts []Option) []string {
	keys := make([]string, 0, len(opts))
	for _, o := range opts {
		keys = append(keys, o.Key)
	}
	return keys
}

// 验证完整规则的头部 7 个字段以及选项顺序与取值是否正确。
func TestLexFullRule(t *testing.T) {
	line := `alert tcp any any -> any any (msg:"hello"; flow:to_server; content:"foo"; nocase; http_uri; content:"bar"; sid:1001; rev:1; classtype:web-application-attack;)`
	r, err := Lex(line, 1)
	if err != nil {
		t.Fatalf("Lex 返回错误: 期望 nil, 实际 %v", err)
	}
	if r == nil {
		t.Fatal("Lex 返回 nil 规则: 期望非 nil, 实际 nil")
	}

	got := []string{r.Header.Action, r.Header.Proto, r.Header.SrcIP, r.Header.SrcPort,
		r.Header.Direction, r.Header.DstIP, r.Header.DstPort}
	want := []string{"alert", "tcp", "any", "any", "->", "any", "any"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("头部第 %d 个字段: 期望 %q, 实际 %q", i+1, want[i], got[i])
		}
	}

	wantKeys := []string{"msg", "flow", "content", "nocase", "http_uri", "content", "sid", "rev", "classtype"}
	keys := optKeys(r.Options)
	if strings.Join(keys, ",") != strings.Join(wantKeys, ",") {
		t.Fatalf("选项顺序: 期望 %v, 实际 %v", wantKeys, keys)
	}

	if v, _ := optVal(r.Options, "msg"); v != "hello" {
		t.Errorf("msg 值: 期望 %q, 实际 %q", "hello", v)
	}
	if v, ok := optVal(r.Options, "nocase"); !ok || v != "" {
		t.Errorf("nocase 值: 期望空串, 实际 %q (存在=%v)", v, ok)
	}
	if v, ok := optVal(r.Options, "http_uri"); !ok || v != "" {
		t.Errorf("http_uri 值: 期望空串, 实际 %q (存在=%v)", v, ok)
	}
	if v, _ := optVal(r.Options, "sid"); v != "1001" {
		t.Errorf("sid 值: 期望 %q, 实际 %q", "1001", v)
	}
	if v, _ := optVal(r.Options, "classtype"); v != "web-application-attack" {
		t.Errorf("classtype 值: 期望 %q, 实际 %q", "web-application-attack", v)
	}
}

// 验证引号内的括号与分号不会被当作分隔符。
func TestLexQuotedSeparators(t *testing.T) {
	line := `alert tcp any any -> any any (content:"foo(bar);baz"; sid:1;)`
	r, err := Lex(line, 1)
	if err != nil {
		t.Fatalf("Lex 返回错误: 期望 nil, 实际 %v", err)
	}
	v, ok := optVal(r.Options, "content")
	if !ok {
		t.Fatalf("未找到 content 选项: 期望存在, 实际选项 %v", optKeys(r.Options))
	}
	if v != "foo(bar);baz" {
		t.Errorf("content 值: 期望 %q, 实际 %q", "foo(bar);baz", v)
	}
	if idx := optIndexOf(r.Options, "sid"); idx < 0 {
		t.Errorf("sid 选项丢失: 期望存在, 实际选项 %v", optKeys(r.Options))
	}
}

// 验证头部中的 IP 列表与端口列表被整体保留。
func TestLexHeaderLists(t *testing.T) {
	line := `alert tcp [10.0.0.0/8,192.168.0.0/16] any -> any [80,443] (msg:"x"; sid:1;)`
	r, err := Lex(line, 1)
	if err != nil {
		t.Fatalf("Lex 返回错误: 期望 nil, 实际 %v", err)
	}
	if r.Header.SrcIP != "[10.0.0.0/8,192.168.0.0/16]" {
		t.Errorf("SrcIP: 期望 %q, 实际 %q", "[10.0.0.0/8,192.168.0.0/16]", r.Header.SrcIP)
	}
	if r.Header.DstPort != "[80,443]" {
		t.Errorf("DstPort: 期望 %q, 实际 %q", "[80,443]", r.Header.DstPort)
	}
}

// 验证双向方向符 <> 被接受并原样保留。
func TestLexBidirectional(t *testing.T) {
	line := `alert tcp any any <> any any (msg:"bi"; sid:1;)`
	r, err := Lex(line, 1)
	if err != nil {
		t.Fatalf("Lex 返回错误: 期望 nil, 实际 %v", err)
	}
	if r.Header.Direction != "<>" {
		t.Errorf("Direction: 期望 %q, 实际 %q", "<>", r.Header.Direction)
	}
}

// 验证引号内的转义序列被还原（\" -> "，\\ -> \）。
func TestLexEscapes(t *testing.T) {
	line := `alert tcp any any -> any any (msg:"a\"b\\c"; sid:1;)`
	r, err := Lex(line, 1)
	if err != nil {
		t.Fatalf("Lex 返回错误: 期望 nil, 实际 %v", err)
	}
	v, ok := optVal(r.Options, "msg")
	if !ok {
		t.Fatalf("未找到 msg 选项: 期望存在, 实际选项 %v", optKeys(r.Options))
	}
	if v != `a"b\c` {
		t.Errorf("msg 值: 期望 %q, 实际 %q", `a"b\c`, v)
	}
}

// 验证字段数不足与括号不配对两条错误路径都能返回 error。
func TestLexErrors(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"字段数不足", `alert tcp any any -> any`},
		{"括号不配对", `alert tcp any any -> any any (sid:1;`},
	}
	for _, tc := range cases {
		r, err := Lex(tc.line, 1)
		if err == nil {
			t.Errorf("%s: 期望返回 error, 实际 nil (规则=%v)", tc.name, r)
		}
	}
}

// 验证 LexAll 跳过空行与注释行、隔离单行失败并给出真实行号。
func TestLexAllSkipsAndIsolates(t *testing.T) {
	text := "# comment line\n" +
		"\n" +
		"alert tcp any any -> any any (msg:\"ok1\"; sid:1;)\n" +
		"alert tcp any any -> any\n" +
		"alert tcp any any -> any any (msg:\"ok2\"; sid:2;)\n"

	rules, lexErrs := LexAll(text)
	if len(rules) != 2 {
		t.Fatalf("LexAll 规则数: 期望 2, 实际 %d", len(rules))
	}
	if len(lexErrs) != 1 {
		t.Fatalf("LexAll 错误数: 期望 1, 实际 %d", len(lexErrs))
	}
	if lexErrs[0].Line != 4 {
		t.Errorf("LexAll 错误行号: 期望 4, 实际 %d", lexErrs[0].Line)
	}
	if rules[0].Line != 3 {
		t.Errorf("第一条规则行号: 期望 3, 实际 %d", rules[0].Line)
	}
	if rules[1].Line != 5 {
		t.Errorf("第二条规则行号: 期望 5, 实际 %d", rules[1].Line)
	}
	if !strings.Contains(rules[0].Text, "ok1") || !strings.Contains(rules[1].Text, "ok2") {
		t.Errorf("规则 Text 未保留原文: 期望分别含 ok1/ok2, 实际 %q / %q", rules[0].Text, rules[1].Text)
	}
}
