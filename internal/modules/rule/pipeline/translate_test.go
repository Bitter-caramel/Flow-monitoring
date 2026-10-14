package pipeline

import (
	"testing"

	"flow-monitoring/internal/modules/rule"
)

// TestTranslate 验证新翻译入口 Translate 自身的行为：元信息/动作、规则头、内容条件与匹配器、缺省值、坏行隔离与空输入。
func TestTranslate(t *testing.T) {
	// 一条完整规则，且不含 content（因此不应产生任何条件/匹配器）。
	text := `alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"ET SQLi"; flow:to_server,established; sid:2100498; rev:3; classtype:web-application-attack; reference:cve,2021-1234;)`

	got := Translate(text)
	if got.Total != 1 || got.Compiled != 1 || got.Failed != 0 {
		t.Fatalf("统计 = Total=%d Compiled=%d Failed=%d，期望 1/1/0", got.Total, got.Compiled, got.Failed)
	}
	if len(got.Rules) != 1 {
		t.Fatalf("规则数 = %d，期望 1", len(got.Rules))
	}
	nr := got.Rules[0]

	if nr.ID != "suricata-2100498" || nr.Source != rule.SourceSuricata || nr.SourceID != "2100498" {
		t.Errorf("ID/Source/SourceID = %q/%q/%q，期望 suricata-2100498/%q/2100498",
			nr.ID, nr.Source, nr.SourceID, rule.SourceSuricata)
	}
	if nr.Name != "ET SQLi" || nr.Category != "web" || nr.Severity != "high" || !nr.Enabled {
		t.Errorf("元信息 = name=%q cat=%q sev=%q enabled=%v，期望 ET SQLi/web/high/true",
			nr.Name, nr.Category, nr.Severity, nr.Enabled)
	}
	if nr.Action.Kind != "web-application-attack" || nr.Action.Severity != "high" ||
		nr.Action.Weight != 80 || nr.Action.Confidence != 1.0 {
		t.Errorf("Action = %+v，期望 kind=web-application-attack sev=high weight=80 conf=1", nr.Action)
	}
	if nr.Match.Proto != rule.ProtoTCP {
		t.Errorf("Proto = %q，期望 %q", nr.Match.Proto, rule.ProtoTCP)
	}
	if len(nr.Match.SrcIP.Networks) != 1 || nr.Match.SrcIP.Networks[0] != "$HOME_NET" {
		t.Errorf("SrcIP = %+v，期望 Networks=[$HOME_NET]", nr.Match.SrcIP)
	}
	if !nr.Match.SrcPort.Any {
		t.Errorf("SrcPort = %+v，期望 any", nr.Match.SrcPort)
	}
	if nr.Match.DstPort.Any || len(nr.Match.DstPort.Ports) != 1 || nr.Match.DstPort.Ports[0] != 80 {
		t.Errorf("DstPort = %+v，期望 Ports=[80]", nr.Match.DstPort)
	}
	if nr.Match.Flow != rule.FlowEstablished {
		t.Errorf("Flow = %q，期望 %q", nr.Match.Flow, rule.FlowEstablished)
	}
	if len(nr.References) != 1 || nr.References[0] != "cve,2021-1234" {
		t.Errorf("References = %#v，期望 [cve,2021-1234]", nr.References)
	}
	// 该规则无 content，因此 Conditions 与 Matchers 都应为 0（也不该触发丢光条件的安全阀）。
	if len(nr.Match.Conditions) != 0 || len(nr.Matchers) != 0 {
		t.Errorf("Conditions/Matchers = %d/%d，期望 0/0", len(nr.Match.Conditions), len(nr.Matchers))
	}

	// 带内容的规则：验证条件与匹配器的翻译。
	withContent := Translate(`alert tcp any any -> any 80 (msg:"x"; content:"union select"; nocase; http_uri; content:"/admin"; sid:5;)`)
	if withContent.Total != 1 || withContent.Compiled != 1 || withContent.Failed != 0 {
		t.Fatalf("内容规则统计 = Total=%d Compiled=%d Failed=%d，期望 1/1/0",
			withContent.Total, withContent.Compiled, withContent.Failed)
	}
	if len(withContent.Rules) != 1 {
		t.Fatalf("内容规则数 = %d，期望 1", len(withContent.Rules))
	}
	cr := withContent.Rules[0]
	if len(cr.Match.Conditions) != 2 {
		t.Fatalf("内容规则 Conditions = %d，期望 2", len(cr.Match.Conditions))
	}
	for i, c := range cr.Match.Conditions {
		if c.Kind != rule.CondContent {
			t.Errorf("Conditions[%d].Kind = %q，期望 %q", i, c.Kind, rule.CondContent)
		}
	}
	if cr.Match.Conditions[0].Buffer != rule.BufStream || cr.Match.Conditions[0].Flags&rule.FlagNoCase == 0 {
		t.Errorf("Conditions[0] = %+v，期望 Buffer=%q 且带 FlagNoCase", cr.Match.Conditions[0], rule.BufStream)
	}
	if cr.Match.Conditions[1].Buffer != rule.BufHTTPURI {
		t.Errorf("Conditions[1].Buffer = %q，期望 %q", cr.Match.Conditions[1].Buffer, rule.BufHTTPURI)
	}
	if len(cr.Matchers) != 2 {
		t.Fatalf("内容规则 Matchers = %d，期望 2", len(cr.Matchers))
	}
	if cr.Matchers[0].Lower != "union select" {
		t.Errorf("Matchers[0].Lower = %q，期望 %q", cr.Matchers[0].Lower, "union select")
	}

	// 无 classtype → 默认分类/严重度 + suricata_alert。
	def := Translate(`alert udp any any -> any 53 (msg:"dns"; sid:7;)`)
	if len(def.Rules) != 1 {
		t.Fatalf("默认规则数 = %d，期望 1", len(def.Rules))
	}
	dr := def.Rules[0]
	if dr.Category != "unknown" || dr.Severity != "medium" || dr.Action.Kind != "suricata_alert" ||
		dr.Action.Weight != 50 || dr.Match.Proto != rule.ProtoUDP {
		t.Errorf("默认值 = %+v / %+v，期望 category=unknown sev=medium kind=suricata_alert weight=50 proto=%q",
			dr.Rule, dr.Action, rule.ProtoUDP)
	}

	// 坏行隔离：注释行（# c）被忽略；"bad line here" 与 sid 非法的行都是词法错误。
	// 口径：Total = 词法成功条数 + 词法失败条数（此处 0 + 2 = 2）。
	bad := Translate("# c\nbad line here\nalert tcp any any -> any 80 (sid:notanumber;)\n")
	if bad.Total != 2 || bad.Compiled != 0 || bad.Failed != 2 {
		t.Errorf("坏行统计 = Total=%d Compiled=%d Failed=%d，期望 2/0/2", bad.Total, bad.Compiled, bad.Failed)
	}
	if len(bad.LexErrors) != 2 {
		t.Fatalf("坏行 LexErrors = %d，期望 2", len(bad.LexErrors))
	}
	// 第一条词法错误对应原文第 2 行 "bad line here"（行号从 1 开始）。
	if bad.LexErrors[0].Line != 2 || bad.LexErrors[0].Text != "bad line here" {
		t.Errorf("LexErrors[0] = line=%d text=%q，期望 line=2 text=%q",
			bad.LexErrors[0].Line, bad.LexErrors[0].Text, "bad line here")
	}

	// 空输入：统计全为 0，且四个集合字段都非 nil。
	empty := Translate("")
	if empty.Total != 0 || empty.Compiled != 0 || empty.Failed != 0 {
		t.Errorf("空输入统计 = Total=%d Compiled=%d Failed=%d，期望 0/0/0",
			empty.Total, empty.Compiled, empty.Failed)
	}
	if empty.Rules == nil || empty.LexErrors == nil || empty.CompileErrs == nil || empty.Unsupported == nil {
		t.Errorf("空输入集合字段不应为 nil：Rules=%v LexErrors=%v CompileErrs=%v Unsupported=%v",
			empty.Rules == nil, empty.LexErrors == nil, empty.CompileErrs == nil, empty.Unsupported == nil)
	}
}
