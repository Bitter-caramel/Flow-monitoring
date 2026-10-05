package rule

import (
	"strconv"
	"strings"

	"flow-monitoring/internal/modules/rule/suricata"
)

// classtypeTable 是内置的 Suricata Classtype 到 [分类, 严重度] 的映射表。
var classtypeTable = map[string][2]string{
	"web-application-attack": {"web", "high"},
	"attempted-admin":        {"web", "medium"},
	"attempted-user":         {"web", "low"},
	"trojan-activity":        {"c2", "high"},
	"scan":                   {"scanner", "medium"},
	"attempted-recon":        {"scanner", "medium"},
	"attempted-dos":          {"proto", "high"},
	"misc-attack":            {"proto", "medium"},
	"misc-activity":          {"proto", "medium"},
	"policy-violation":       {"proto", "low"},
}

// Normalize 将一条 Suricata 解析结果转换为内部统一的 Rule 表示。
func Normalize(pr *suricata.ParsedRule) *Rule {
	if pr == nil {
		return nil
	}

	sid := strconv.Itoa(pr.SID)
	category, severity := "unknown", "medium"
	if v, ok := classtypeTable[pr.Classtype]; ok {
		category, severity = v[0], v[1]
	}

	r := &Rule{
		ID:         "suricata-" + sid,
		Source:     SourceSuricata,
		SourceID:   sid,
		Name:       pr.Message,
		Category:   category,
		Severity:   severity,
		References: pr.References,
		Enabled:    true,
	}

	r.Match = Match{
		Proto:   mapProto(pr.Proto),
		SrcIP:   parseNetSpec(pr.SrcIP),
		DstIP:   parseNetSpec(pr.DstIP),
		SrcPort: parsePortSpec(pr.SrcPort),
		DstPort: parsePortSpec(pr.DstPort),
		Flow:    mapFlow(pr.Flow),
	}

	for _, c := range pr.Contents {
		var flags CondFlags
		if c.NoCase {
			flags |= FlagNoCase
		}
		if c.Negate {
			flags |= FlagNegate
		}
		if c.FastPattern {
			flags |= FlagFastPattern
		}
		r.Match.Conditions = append(r.Match.Conditions, Condition{
			Kind:   CondContent,
			Buffer: mapBuffer(c.Buffer),
			Value:  c.Value,
			Flags:  flags,
			Offset: c.Offset,
			Depth:  c.Depth,
		})
	}

	for _, p := range pr.PCRES {
		var flags CondFlags
		if p.Negate {
			flags |= FlagNegate
		}
		r.Match.Conditions = append(r.Match.Conditions, Condition{
			Kind:   CondPCRE,
			Buffer: mapBuffer(p.Buffer),
			Value:  p.Expr,
			Flags:  flags,
		})
	}

	actionKind := pr.Classtype
	if actionKind == "" {
		actionKind = "suricata_alert"
	}
	r.Action = Action{
		Kind:       actionKind,
		Severity:   severity,
		Weight:     severityWeight(severity),
		Confidence: 1.0,
	}

	return r
}

// NormalizeAll 批量转换 Suricata 解析结果，返回非 nil 的 Rule 切片。
func NormalizeAll(parsed []*suricata.ParsedRule) []*Rule {
	rules := make([]*Rule, 0, len(parsed))
	for _, pr := range parsed {
		if pr == nil {
			continue
		}
		rules = append(rules, Normalize(pr))
	}
	return rules
}

// parseNetSpec 解析 Suricata 的地址字段，支持取反、any 以及 [ ] 包裹的列表。
func parseNetSpec(s string) NetSpec {
	s = strings.TrimSpace(s)

	var negate bool
	if strings.HasPrefix(s, "!") {
		negate = true
		s = strings.TrimSpace(strings.TrimPrefix(s, "!"))
	}
	if s == "" || s == "any" {
		return NetSpec{}
	}

	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	}

	var networks []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			networks = append(networks, part)
		}
	}
	return NetSpec{Negate: negate, Networks: networks}
}

// parsePortSpec 解析 Suricata 的端口字段，支持 any、拼接范围以及取反（暂不支持）。
func parsePortSpec(s string) PortSpec {
	s = strings.TrimSpace(s)

	if strings.HasPrefix(s, "!") {
		return PortSpec{Any: true}
	}
	if s == "" || s == "any" {
		return PortSpec{Any: true}
	}

	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	}

	var spec PortSpec
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, ":") {
			fields := strings.SplitN(part, ":", 2)
			from, err1 := strconv.Atoi(strings.TrimSpace(fields[0]))
			to, err2 := strconv.Atoi(strings.TrimSpace(fields[1]))
			if err1 != nil || err2 != nil {
				continue
			}
			spec.Ranges = append(spec.Ranges, PortRange{From: uint16(from), To: uint16(to)})
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		spec.Ports = append(spec.Ports, uint16(p))
	}
	return spec
}

// mapFlow 将 Suricata 的 flow 关键字列表映射为统一的 FlowSpec。
func mapFlow(flow []string) FlowSpec {
	for _, f := range flow {
		if f == "stateless" {
			return FlowStateless
		}
	}
	for _, f := range flow {
		if f == "established" {
			return FlowEstablished
		}
	}
	for _, f := range flow {
		if f == "to_server" || f == "from_client" {
			return FlowToServer
		}
	}
	return ""
}

// mapBuffer 将 Suricata 的缓冲区名映射为统一的 Buffer 取值。
func mapBuffer(name string) Buffer {
	switch name {
	case "payload":
		return BufPayload
	case "http_uri":
		return BufHTTPURI
	case "http_header":
		return BufHTTPHeader
	case "http_method":
		return BufHTTPMethod
	case "http_client_body":
		return BufHTTPClientBody
	case "dns_query":
		return BufDNSQuery
	case "tls_sni":
		return BufTLSSNI
	default:
		return BufPayload
	}
}

// mapProto 将 Suricata 的协议名映射为统一的 Protocol 取值。
func mapProto(proto string) Protocol {
	switch proto {
	case "tcp":
		return ProtoTCP
	case "udp":
		return ProtoUDP
	case "icmp":
		return ProtoICMP
	case "http":
		return ProtoHTTP
	case "dns":
		return ProtoDNS
	case "tls":
		return ProtoTLS
	case "ssh":
		return ProtoSSH
	default:
		return ProtoAny
	}
}

// severityWeight 按严重度返回对应的动作权重。
func severityWeight(severity string) int {
	switch severity {
	case "critical":
		return 100
	case "high":
		return 80
	case "medium":
		return 50
	case "low":
		return 20
	default:
		return 50
	}
}
