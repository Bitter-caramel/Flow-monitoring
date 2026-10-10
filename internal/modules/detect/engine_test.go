package detect

import (
	"regexp"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/modules/rule"
)

// extOf 通过缓冲名取提取器；取不到直接失败（顺带验证注册表）。
func extOf(t *testing.T, buf rule.Buffer) Extractor {
	t.Helper()
	fn, ok := LookupBuffer(buf)
	if !ok {
		t.Fatalf("缓冲区未注册: %s", buf)
	}
	return fn
}

// payloadPkt 构造一个 payload 从 0 开始的包。
func payloadPkt(payload string) *datamodel.Packet {
	return &datamodel.Packet{
		Data:       []byte(payload),
		PayloadOff: 0,
		PayloadLen: len(payload),
		Time:       time.Unix(1700000000, 0),
	}
}

// anyPort 返回「不做端口筛选」的 PortSpec。
func anyPort() rule.PortSpec { return rule.PortSpec{Any: true} }

// 验证 a)：条件按序 + last 推进 —— 第二个 content 相对第一个的结束位置才成立。
func TestMatchSequentialLastAdvances(t *testing.T) {
	ex := extOf(t, rule.BufPayload)
	prog := &Program{
		ID: "r-seq", Name: "顺序匹配", Severity: "high",
		Proto: rule.ProtoAny, SrcPort: anyPort(), DstPort: anyPort(),
		Conds: []Cond{
			{Kind: rule.CondContent, Extract: ex, Buf: rule.BufPayload, Content: []byte("GET ")},
			{Kind: rule.CondContent, Extract: ex, Buf: rule.BufPayload, Content: []byte("HTTP/1.1")},
		},
	}
	eng := NewEngine([]*Program{prog})

	// 按序且相对上次匹配位置成立 → 命中
	got := eng.Match(&Ctx{Pkt: payloadPkt("GET /a HTTP/1.1\r\n")})
	if len(got) != 1 {
		t.Fatalf("按序流量应命中 1 条, got=%d", len(got))
	}
	if got[0].RuleID != "r-seq" || got[0].Buffer != rule.BufPayload || got[0].Offset != 0 {
		t.Fatalf("告警字段不对: %+v", got[0])
	}

	// 两者各自单独出现、但顺序相反 → 不命中
	if other := eng.Match(&Ctx{Pkt: payloadPkt("HTTP/1.1 GET /")}); len(other) != 0 {
		t.Fatalf("顺序相反的流量不应命中, got=%d", len(other))
	}
}

// 验证 b)：depth 只在窗口内搜索 —— 窗口外不命中、窗口内命中。
func TestMatchDepthWindow(t *testing.T) {
	ex := extOf(t, rule.BufPayload)
	mk := func(depth int) *Program {
		return &Program{
			ID: "r-depth", Proto: rule.ProtoAny, SrcPort: anyPort(), DstPort: anyPort(),
			Conds: []Cond{{Kind: rule.CondContent, Extract: ex, Buf: rule.BufPayload,
				Content: []byte("zzz"), Offset: 0, Depth: depth}},
		}
	}
	// "zzz" 在偏移 5；depth=4 窗口 [0,4) 不含它 → 不命中
	if got := NewEngine([]*Program{mk(4)}).Match(&Ctx{Pkt: payloadPkt("aaaa zzz")}); len(got) != 0 {
		t.Fatalf("窗口外不应命中, got=%d", len(got))
	}
	// depth=16 窗口覆盖到缓冲末尾 → 命中
	if got := NewEngine([]*Program{mk(16)}).Match(&Ctx{Pkt: payloadPkt("aaaa zzz")}); len(got) != 1 {
		t.Fatalf("窗口内应命中, got=%d", len(got))
	}
}

// 验证 c)：nocase —— 模式 "union" 命中被匹配字节里的大写 "UNION"。
func TestMatchNoCase(t *testing.T) {
	ex := extOf(t, rule.BufPayload)
	prog := &Program{
		ID: "r-nocase", Proto: rule.ProtoAny, SrcPort: anyPort(), DstPort: anyPort(),
		Conds: []Cond{{Kind: rule.CondContent, Extract: ex, Buf: rule.BufPayload,
			Content: []byte("union"), Lower: []byte("union")}},
	}
	got := NewEngine([]*Program{prog}).Match(&Ctx{Pkt: payloadPkt("SELECT UNION ALL")})
	if len(got) != 1 {
		t.Fatalf("nocase 应命中大写 UNION, got=%d", len(got))
	}
}

// 验证 d)：negate —— 模式不存在才命中，存在则不命中。
func TestMatchNegate(t *testing.T) {
	ex := extOf(t, rule.BufPayload)
	prog := &Program{
		ID: "r-negate", Proto: rule.ProtoAny, SrcPort: anyPort(), DstPort: anyPort(),
		Conds: []Cond{{Kind: rule.CondContent, Extract: ex, Buf: rule.BufPayload,
			Content: []byte("sqlmap"), Negate: true}},
	}
	eng := NewEngine([]*Program{prog})
	if got := eng.Match(&Ctx{Pkt: payloadPkt("hello world")}); len(got) != 1 {
		t.Fatalf("模式不存在时 negate 应命中, got=%d", len(got))
	}
	if got := eng.Match(&Ctx{Pkt: payloadPkt("run sqlmap now")}); len(got) != 0 {
		t.Fatalf("模式存在时 negate 不应命中, got=%d", len(got))
	}
}

// 验证 e)：pcre 正则命中 / 不命中各一。
func TestMatchPCRE(t *testing.T) {
	ex := extOf(t, rule.BufPayload)
	prog := &Program{
		ID: "r-pcre", Proto: rule.ProtoAny, SrcPort: anyPort(), DstPort: anyPort(),
		Conds: []Cond{{Kind: rule.CondPCRE, Extract: ex, Buf: rule.BufPayload,
			Regex: regexp.MustCompile(`(?i)select.+from`)}},
	}
	eng := NewEngine([]*Program{prog})
	if got := eng.Match(&Ctx{Pkt: payloadPkt("SELECT a FROM t")}); len(got) != 1 {
		t.Fatalf("pcre 应命中, got=%d", len(got))
	}
	if got := eng.Match(&Ctx{Pkt: payloadPkt("hello world")}); len(got) != 0 {
		t.Fatalf("pcre 不应命中, got=%d", len(got))
	}
}

// 验证 f)：缓冲不存在 × 取反（§5.4）—— http_uri + content:!"x"，喂非 HTTP 包必须不命中。
func TestMatchNegateMissingBuffer(t *testing.T) {
	ex := extOf(t, rule.BufHTTPURI)
	prog := &Program{
		ID: "r-uri", Proto: rule.ProtoAny, SrcPort: anyPort(), DstPort: anyPort(),
		Conds: []Cond{{Kind: rule.CondContent, Extract: ex, Buf: rule.BufHTTPURI,
			Content: []byte("x"), Negate: true}},
	}
	pkt := &datamodel.Packet{ // HTTP == nil → 非 HTTP 包
		Data: []byte("GET /x HTTP/1.1\r\n"), PayloadOff: 0, PayloadLen: len("GET /x HTTP/1.1\r\n"),
	}
	if got := NewEngine([]*Program{prog}).Match(&Ctx{Pkt: pkt}); len(got) != 0 {
		t.Fatalf("缓冲不存在的取反条件必须整条不命中, got=%d", len(got))
	}
}

// 验证 g)：端口必须分源 / 目的 —— 规则 SrcPort=1024:65535、DstPort=80。
func TestMatchPortsSeparateSrcDst(t *testing.T) {
	ex := extOf(t, rule.BufPayload)
	prog := &Program{
		ID: "r-port", Proto: rule.ProtoAny,
		SrcPort: rule.PortSpec{Ranges: []rule.PortRange{{From: 1024, To: 65535}}},
		DstPort: rule.PortSpec{Ports: []uint16{80}},
		Conds:   []Cond{{Kind: rule.CondContent, Extract: ex, Buf: rule.BufPayload, Content: []byte("GET")}},
	}
	eng := NewEngine([]*Program{prog})
	mk := func(sp, dp uint16) *datamodel.Packet {
		return &datamodel.Packet{Data: []byte("GET /"), PayloadOff: 0, PayloadLen: len("GET /"), SrcPort: sp, DstPort: dp}
	}
	// 源 50000 / 目的 9999 → 目的端口不过 → 不命中
	if got := eng.Match(&Ctx{Pkt: mk(50000, 9999)}); len(got) != 0 {
		t.Fatalf("目的端口不匹配不应命中, got=%d", len(got))
	}
	// 源 80 / 目的 80 → 源端口不过（80 < 1024）→ 不命中（证明确实分了源 / 目的）
	if got := eng.Match(&Ctx{Pkt: mk(80, 80)}); len(got) != 0 {
		t.Fatalf("源端口不匹配不应命中, got=%d", len(got))
	}
	// 源 50000 / 目的 80 → 命中
	if got := eng.Match(&Ctx{Pkt: mk(50000, 80)}); len(got) != 1 {
		t.Fatalf("源 / 目的都匹配应命中, got=%d", len(got))
	}
}

// 验证 h)：flow 筛选 —— established 看状态、stateless 不看状态。
func TestMatchFlowFilter(t *testing.T) {
	ex := extOf(t, rule.BufPayload)
	cond := Cond{Kind: rule.CondContent, Extract: ex, Buf: rule.BufPayload, Content: []byte("x")}
	est := &Program{ID: "r-est", Proto: rule.ProtoAny, SrcPort: anyPort(), DstPort: anyPort(),
		Flow: rule.FlowEstablished, Conds: []Cond{cond}}
	anyRule := &Program{ID: "r-any", Proto: rule.ProtoAny, SrcPort: anyPort(), DstPort: anyPort(),
		Flow: rule.FlowStateless, Conds: []Cond{cond}}
	pkt := payloadPkt("x")

	// FlowEstablished + FlowEstablished → 命中
	if got := NewEngine([]*Program{est}).Match(&Ctx{Pkt: pkt, Flow: &datamodel.Flow{State: datamodel.FlowEstablished}}); len(got) != 1 {
		t.Fatalf("established 流应命中, got=%d", len(got))
	}
	// FlowEstablished + FlowUnknown → 不命中
	if got := NewEngine([]*Program{est}).Match(&Ctx{Pkt: pkt, Flow: &datamodel.Flow{State: datamodel.FlowUnknown}}); len(got) != 0 {
		t.Fatalf("未知状态不应命中, got=%d", len(got))
	}
	// FlowEstablished + Flow == nil → 不命中
	if got := NewEngine([]*Program{est}).Match(&Ctx{Pkt: pkt}); len(got) != 0 {
		t.Fatalf("Flow 为 nil 不应命中, got=%d", len(got))
	}
	// FlowStateless 不看状态也能命中
	if got := NewEngine([]*Program{anyRule}).Match(&Ctx{Pkt: pkt, Flow: &datamodel.Flow{State: datamodel.FlowUnknown}}); len(got) != 1 {
		t.Fatalf("stateless 不看状态应命中, got=%d", len(got))
	}
}

// 验证 i)：无命中返回空；空规则集 / NewEngine(nil) / nil Ctx 都不 panic。
func TestMatchNoHitAndEmptyEngine(t *testing.T) {
	ex := extOf(t, rule.BufPayload)
	prog := &Program{ID: "r-nohit", Proto: rule.ProtoAny, SrcPort: anyPort(), DstPort: anyPort(),
		Conds: []Cond{{Kind: rule.CondContent, Extract: ex, Buf: rule.BufPayload, Content: []byte("needle")}}}
	if got := NewEngine([]*Program{prog}).Match(&Ctx{Pkt: payloadPkt("haystack")}); len(got) != 0 {
		t.Fatalf("无命中应为空, got=%d", len(got))
	}

	eng := NewEngine(nil)
	if eng == nil {
		t.Fatal("NewEngine(nil) 不应返回 nil")
	}
	if eng.RuleCount() != 0 {
		t.Fatalf("空引擎 RuleCount = %d, want 0", eng.RuleCount())
	}
	if got := eng.Match(&Ctx{Pkt: payloadPkt("x")}); len(got) != 0 {
		t.Fatalf("空引擎应为空, got=%d", len(got))
	}
	if got := eng.Match(nil); len(got) != 0 {
		t.Fatalf("nil Ctx 应为空, got=%d", len(got))
	}
	if got := eng.Match(&Ctx{}); len(got) != 0 {
		t.Fatalf("nil Pkt 应为空, got=%d", len(got))
	}
	// 含 nil 元素的规则集也不该 panic
	if got := NewEngine([]*Program{nil}).Match(&Ctx{Pkt: payloadPkt("x")}); len(got) != 0 {
		t.Fatalf("含 nil 规则应为空, got=%d", len(got))
	}
}

// 验证改动 3：Compile 从 cr.Match 原样复制 SrcPort/DstPort（保留源/目的区分），
// 并在 flow 为 to_server 时把「方向条件未生效」记进 Unsupported。
func TestCompileCopiesPortSpecAndReportsFlowToServer(t *testing.T) {
	mkCR := func(flow rule.FlowSpec) *rule.CompiledRule {
		cr := &rule.CompiledRule{
			Rule: rule.Rule{ID: "r1", Name: "m", Severity: "low"},
			Matchers: []rule.Matcher{
				{Kind: rule.CondContent, Buffer: rule.BufPayload, Content: "x"},
			},
		}
		cr.Match.Proto = rule.ProtoAny
		cr.Match.Flow = flow
		cr.Match.SrcPort = rule.PortSpec{Ranges: []rule.PortRange{{From: 1024, To: 65535}}}
		cr.Match.DstPort = rule.PortSpec{Ports: []uint16{80}}
		return cr
	}

	// 源/目的端口从 cr.Match 复制，而不是合并过的 AnyPort/Ports/Ranges。
	p, err := Compile(mkCR(rule.FlowStateless))
	if err != nil {
		t.Fatalf("Compile 失败: %v", err)
	}
	if p.SrcPort.Any || len(p.SrcPort.Ranges) != 1 || p.SrcPort.Ranges[0].From != 1024 || p.SrcPort.Ranges[0].To != 65535 {
		t.Fatalf("SrcPort 未从 cr.Match 复制: %+v", p.SrcPort)
	}
	if len(p.DstPort.Ports) != 1 || p.DstPort.Ports[0] != 80 {
		t.Fatalf("DstPort 未从 cr.Match 复制: %+v", p.DstPort)
	}
	if len(p.Unsupported) != 0 {
		t.Fatalf("stateless 不应有 Unsupported: %v", p.Unsupported)
	}

	// to_server → 追加「方向条件未生效」。
	p2, err := Compile(mkCR(rule.FlowToServer))
	if err != nil {
		t.Fatalf("Compile 失败: %v", err)
	}
	if len(p2.Unsupported) != 1 {
		t.Fatalf("to_server 应记 1 条 Unsupported, got=%v", p2.Unsupported)
	}
}

// a) 规则 Proto=TCP；包 IPProto=6 且展示名被 HTTP 覆盖成 "HTTP" → 必须命中。
func TestMatchProtoTCPDespiteDisplayName(t *testing.T) {
	ex := extOf(t, rule.BufPayload)
	prog := &Program{ID: "r-tcp-hit", Proto: rule.ProtoTCP, SrcPort: anyPort(), DstPort: anyPort(),
		Conds: []Cond{{Kind: rule.CondContent, Extract: ex, Buf: rule.BufPayload, Content: []byte("GET")}}}
	pkt := &datamodel.Packet{Data: []byte("GET /x"), PayloadOff: 0, PayloadLen: len("GET /x"), IPProto: 6, Proto: "HTTP"}
	if got := NewEngine([]*Program{prog}).Match(&Ctx{Pkt: pkt}); len(got) != 1 {
		t.Fatalf("Proto=TCP 且 IPProto=6 应命中（展示名 HTTP 不影响）, got=%d", len(got))
	}
}

// b) 规则 Proto=HTTP：HTTP != nil 时命中；HTTP == nil（仅 IPProto=6）时不命中。
func TestMatchProtoHTTPNeedsHTTP(t *testing.T) {
	ex := extOf(t, rule.BufPayload)
	prog := &Program{ID: "r-http", Proto: rule.ProtoHTTP, SrcPort: anyPort(), DstPort: anyPort(),
		Conds: []Cond{{Kind: rule.CondContent, Extract: ex, Buf: rule.BufPayload, Content: []byte("GET")}}}
	eng := NewEngine([]*Program{prog})
	withHTTP := &datamodel.Packet{Data: []byte("GET /x"), PayloadOff: 0, PayloadLen: len("GET /x"), IPProto: 6, HTTP: &datamodel.HTTP{}}
	if got := eng.Match(&Ctx{Pkt: withHTTP}); len(got) != 1 {
		t.Fatalf("HTTP != nil 应命中, got=%d", len(got))
	}
	noHTTP := &datamodel.Packet{Data: []byte("GET /x"), PayloadOff: 0, PayloadLen: len("GET /x"), IPProto: 6}
	if got := eng.Match(&Ctx{Pkt: noHTTP}); len(got) != 0 {
		t.Fatalf("HTTP == nil 不应命中, got=%d", len(got))
	}
}

// c) 规则 Proto=TCP；包 IPProto=17（UDP）→ 不命中。
func TestMatchProtoTCPRejectsUDP(t *testing.T) {
	ex := extOf(t, rule.BufPayload)
	prog := &Program{ID: "r-tcp-udp", Proto: rule.ProtoTCP, SrcPort: anyPort(), DstPort: anyPort(),
		Conds: []Cond{{Kind: rule.CondContent, Extract: ex, Buf: rule.BufPayload, Content: []byte("GET")}}}
	pkt := &datamodel.Packet{Data: []byte("GET /x"), PayloadOff: 0, PayloadLen: len("GET /x"), IPProto: 17}
	if got := NewEngine([]*Program{prog}).Match(&Ctx{Pkt: pkt}); len(got) != 0 {
		t.Fatalf("Proto=TCP 遇 IPProto=17 不应命中, got=%d", len(got))
	}
}

// d) 去重：包 IPProto=6 且 HTTP != nil，同一条 Proto=TCP 的规则只能产生 1 条 Alert。
func TestMatchProtoNoDuplicateAlert(t *testing.T) {
	ex := extOf(t, rule.BufPayload)
	prog := &Program{ID: "r-once", Proto: rule.ProtoTCP, SrcPort: anyPort(), DstPort: anyPort(),
		Conds: []Cond{{Kind: rule.CondContent, Extract: ex, Buf: rule.BufPayload, Content: []byte("GET")}}}
	pkt := &datamodel.Packet{Data: []byte("GET /x"), PayloadOff: 0, PayloadLen: len("GET /x"), IPProto: 6, HTTP: &datamodel.HTTP{}}
	if got := NewEngine([]*Program{prog}).Match(&Ctx{Pkt: pkt}); len(got) != 1 {
		t.Fatalf("同一规则只能告警一次, got=%d", len(got))
	}
}

// e) 词表一致性：datamodel 写出的协议名必须与 rule.Protocol 常量逐项一致，防止将来漂移。
func TestProtocolVocabMatchesRuleConstants(t *testing.T) {
	cases := []struct {
		name  string
		proto rule.Protocol
	}{
		{"tcp", rule.ProtoTCP},
		{"udp", rule.ProtoUDP},
		{"icmp", rule.ProtoICMP},
		{"http", rule.ProtoHTTP},
		{"dns", rule.ProtoDNS},
		{"tls", rule.ProtoTLS},
		{"ssh", rule.ProtoSSH},
	}
	for _, c := range cases {
		if string(c.proto) != c.name {
			t.Fatalf("词表漂移: rule.Protocol(%q) 常量名为 %q, 期望 %q", string(c.proto), string(c.proto), c.name)
		}
	}
}
