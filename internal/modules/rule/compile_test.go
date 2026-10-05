package rule

import (
	"strings"
	"testing"
)

// mkRule 构造一个带可用 content 条件的规则，用于编译相关断言。
func mkRule(id string, src, dst PortSpec, conds []Condition) *Rule {
	return &Rule{
		ID:      id,
		Enabled: true,
		Match: Match{
			Proto:      ProtoTCP,
			SrcIP:      NetSpec{Networks: []string{"any"}},
			DstIP:      NetSpec{Networks: []string{"any"}},
			SrcPort:    src,
			DstPort:    dst,
			Conditions: conds,
		},
	}
}

// hasPort 判断端口切片中是否存在指定端口。
func hasPort(ports []uint16, want uint16) bool {
	for _, p := range ports {
		if p == want {
			return true
		}
	}
	return false
}

// hasRange 判断区间切片中是否存在指定区间。
func hasRange(ranges []PortRange, want PortRange) bool {
	for _, r := range ranges {
		if r == want {
			return true
		}
	}
	return false
}

// findMatcher 按条件类型查找一个匹配器。
func findMatcher(c *CompiledRule, kind ConditionKind) (Matcher, bool) {
	for _, m := range c.Matchers {
		if m.Kind == kind {
			return m, true
		}
	}
	return Matcher{}, false
}

// unsupportedContains 判断 Unsupported 中是否存在包含子串 sub 的记录。
func unsupportedContains(c *CompiledRule, sub string) bool {
	for _, u := range c.Unsupported {
		if strings.Contains(u, sub) {
			return true
		}
	}
	return false
}

// 验证端口索引：AnyPort 判定、去重升序端口与端口区间保留。
func TestCompilePortIndex(t *testing.T) {
	content := Condition{Kind: CondContent, Buffer: BufPayload, Value: "abc"}

	// 情况一：源端口为 any、目标端口为具体端口 -> 非 AnyPort，端口为 [80]。
	c1, err := Compile(mkRule("r1", PortSpec{Any: true}, PortSpec{Ports: []uint16{80}}, []Condition{content}))
	if err != nil {
		t.Fatalf("Compile 情况一返回错误: 期望 nil, 实际 %v", err)
	}
	if c1.AnyPort {
		t.Errorf("情况一 AnyPort: 期望 false, 实际 true")
	}
	if len(c1.Ports) != 1 || c1.Ports[0] != 80 {
		t.Errorf("情况一 Ports: 期望 [80], 实际 %v", c1.Ports)
	}

	// 情况二：两侧端口都为 any -> AnyPort 为 true。
	c2, err := Compile(mkRule("r2", PortSpec{Any: true}, PortSpec{Any: true}, []Condition{content}))
	if err != nil {
		t.Fatalf("Compile 情况二返回错误: 期望 nil, 实际 %v", err)
	}
	if !c2.AnyPort {
		t.Errorf("情况二 AnyPort: 期望 true, 实际 false")
	}

	// 情况三：多来源端口去重升序，并保留端口区间。
	dst := PortSpec{Ports: []uint16{80, 8080}, Ranges: []PortRange{{From: 9000, To: 9100}}}
	c3, err := Compile(mkRule("r3", PortSpec{Ports: []uint16{443, 80}}, dst, []Condition{content}))
	if err != nil {
		t.Fatalf("Compile 情况三返回错误: 期望 nil, 实际 %v", err)
	}
	want := []uint16{80, 443, 8080}
	if len(c3.Ports) != len(want) {
		t.Fatalf("情况三 Ports: 期望 %v, 实际 %v", want, c3.Ports)
	}
	for i := range want {
		if c3.Ports[i] != want[i] {
			t.Fatalf("情况三 Ports: 期望 %v, 实际 %v", want, c3.Ports)
		}
	}
	if !hasRange(c3.PortRanges, PortRange{From: 9000, To: 9100}) {
		t.Errorf("情况三 PortRanges: 期望包含 {9000,9100}, 实际 %v", c3.PortRanges)
	}
	if !hasPort(c3.Ports, 8080) || hasPort(c3.Ports, 443) == false {
		t.Errorf("情况三 Ports 内容: 期望含 8080 与 443, 实际 %v", c3.Ports)
	}
}

// 验证 content 匹配器的大小写标志与小写缓存。
func TestCompileContentMatcher(t *testing.T) {
	noCase := Condition{Kind: CondContent, Buffer: BufPayload, Value: "AbC", Flags: FlagNoCase}
	c1, err := Compile(mkRule("r1", PortSpec{Any: true}, PortSpec{Any: true}, []Condition{noCase}))
	if err != nil {
		t.Fatalf("Compile 带 nocase 返回错误: 期望 nil, 实际 %v", err)
	}
	m1, ok := findMatcher(c1, CondContent)
	if !ok {
		t.Fatalf("content 匹配器缺失: 期望存在, 实际 %v", c1.Matchers)
	}
	if !m1.NoCase {
		t.Errorf("带 nocase 的 Matcher.NoCase: 期望 true, 实际 false")
	}
	if m1.Lower != "abc" {
		t.Errorf("带 nocase 的 Matcher.Lower: 期望 %q, 实际 %q", "abc", m1.Lower)
	}

	plain := Condition{Kind: CondContent, Buffer: BufPayload, Value: "AbC"}
	c2, err := Compile(mkRule("r2", PortSpec{Any: true}, PortSpec{Any: true}, []Condition{plain}))
	if err != nil {
		t.Fatalf("Compile 不带 nocase 返回错误: 期望 nil, 实际 %v", err)
	}
	m2, ok := findMatcher(c2, CondContent)
	if !ok {
		t.Fatalf("content 匹配器缺失: 期望存在, 实际 %v", c2.Matchers)
	}
	if m2.Lower != "" {
		t.Errorf("不带 nocase 的 Matcher.Lower: 期望空串, 实际 %q", m2.Lower)
	}
}

// 验证 pcre 条件会被编译成可用的正则匹配器。
func TestCompilePCREMatcher(t *testing.T) {
	cond := Condition{Kind: CondPCRE, Buffer: BufPayload, Value: `/union\s+select/i`}
	c, err := Compile(mkRule("r1", PortSpec{Any: true}, PortSpec{Any: true}, []Condition{cond}))
	if err != nil {
		t.Fatalf("Compile pcre 返回错误: 期望 nil, 实际 %v", err)
	}
	m, ok := findMatcher(c, CondPCRE)
	if !ok {
		t.Fatalf("pcre 匹配器缺失: 期望存在, 实际 %v", c.Matchers)
	}
	if m.Regex == nil {
		t.Fatalf("pcre 匹配器 Regex: 期望非 nil, 实际 nil")
	}
	if !m.Regex.MatchString("UNION   SELECT") {
		t.Errorf("pcre 正则匹配: 期望 %q 命中, 实际未命中", "UNION   SELECT")
	}
}

// 验证 RE2 不支持的正则被跳过并记入 Unsupported，且不影响其它条件编译。
func TestCompileUnsupportedRegexIsSkipped(t *testing.T) {
	conds := []Condition{
		{Kind: CondPCRE, Buffer: BufPayload, Value: `/(?=x)y/`},
		{Kind: CondContent, Buffer: BufPayload, Value: "abc"},
	}
	c, err := Compile(mkRule("r1", PortSpec{Any: true}, PortSpec{Any: true}, conds))
	if err != nil {
		t.Fatalf("Compile 返回错误: 期望 nil (仍有可用 content), 实际 %v", err)
	}
	if _, ok := findMatcher(c, CondPCRE); ok {
		t.Errorf("不支持的正则不应生成 pcre 匹配器: 期望不含 pcre, 实际 %v", c.Matchers)
	}
	if _, ok := findMatcher(c, CondContent); !ok {
		t.Errorf("content 匹配器缺失: 期望存在, 实际 %v", c.Matchers)
	}
	if !unsupportedContains(c, "(?=x)y") {
		t.Errorf("Unsupported 记录: 期望含 %q, 实际 %v", "(?=x)y", c.Unsupported)
	}
}

// 验证安全阀：唯一条件是不可用 pcre 时编译返回 error。
func TestCompileSafetyValve(t *testing.T) {
	conds := []Condition{{Kind: CondPCRE, Buffer: BufPayload, Value: `/(?=x)y/`}}
	c, err := Compile(mkRule("r1", PortSpec{Any: true}, PortSpec{Any: true}, conds))
	if err == nil {
		t.Errorf("Compile: 期望返回 error, 实际 nil (结果 %v)", c)
	}
}

// 验证 Compile(nil) 返回 error 而不是 panic。
func TestCompileNil(t *testing.T) {
	c, err := Compile(nil)
	if err == nil {
		t.Errorf("Compile(nil): 期望返回 error, 实际 nil (结果 %v)", c)
	}
}

// 验证未知条件类型进入 Unsupported，且同规则的 content 仍生成匹配器。
func TestCompileUnknownConditionKind(t *testing.T) {
	conds := []Condition{
		{Kind: ConditionKind("weird"), Buffer: BufPayload, Value: "zzz"},
		{Kind: CondContent, Buffer: BufPayload, Value: "abc"},
	}
	c, err := Compile(mkRule("r1", PortSpec{Any: true}, PortSpec{Any: true}, conds))
	if err != nil {
		t.Fatalf("Compile 返回错误: 期望 nil (仍有可用 content), 实际 %v", err)
	}
	if len(c.Unsupported) == 0 {
		t.Errorf("Unsupported: 期望非空, 实际 %v", c.Unsupported)
	}
	if !unsupportedContains(c, "weird") {
		t.Errorf("Unsupported 记录: 期望含 %q, 实际 %v", "weird", c.Unsupported)
	}
	if _, ok := findMatcher(c, CondContent); !ok {
		t.Errorf("content 匹配器缺失: 期望存在, 实际 %v", c.Matchers)
	}
}

// 验证 CompileAll(nil) 第一个返回值为非 nil 的空切片。
func TestCompileAllNil(t *testing.T) {
	out, _ := CompileAll(nil)
	if out == nil {
		t.Fatalf("CompileAll(nil) 第一个返回值: 期望非 nil, 实际 nil")
	}
	if len(out) != 0 {
		t.Errorf("CompileAll(nil) 长度: 期望 0, 实际 %d", len(out))
	}
}
