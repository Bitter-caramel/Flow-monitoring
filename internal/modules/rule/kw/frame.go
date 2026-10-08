package kw

import (
	"fmt"
	"strconv"
	"strings"

	"flow-monitoring/internal/modules/rule"
	"flow-monitoring/internal/modules/rule/suricata"
)

// NewState 依据词法结果 raw 构造一次规则翻译的初始帧。
//
// 它从 raw.Header 建出 rule.Rule 骨架：默认启用、来源为 Suricata，
// 并按需把协议、源/目的地址与端口映射为 IR 表示。
// ID 与 SourceID 留空，由 meta 层的 sid Handler 负责填。
func NewState(raw *suricata.RawRule) *State {
	r := &rule.Rule{
		Enabled: true,
		Source:  rule.SourceSuricata,
		Match: rule.Match{
			Proto:   mapProto(raw.Header.Proto),
			SrcIP:   parseNetSpec(raw.Header.SrcIP),
			DstIP:   parseNetSpec(raw.Header.DstIP),
			SrcPort: parsePortSpec(raw.Header.SrcPort),
			DstPort: parsePortSpec(raw.Header.DstPort),
		},
	}
	return &State{
		Raw:         raw,
		Rule:        r,
		CurBuf:      rule.BufPayload,
		Unsupported: make(map[string]int),
	}
}

// RunOptions 遍历 raw 中的全部词法选项并分发到对应的关键字 Handler。
//
// 命中已注册关键字时调用其 Handle 处理该选项；若 Handle 返回非 nil error，
// 说明该关键字本身不合法，立即以带关键字名的错误终止并返回；未命中时把该
// 关键字计入 st.Unsupported 的计数，供上层统计“不支持项”。循环正常结束
// 返回 nil。
func RunOptions(st *State) error {
	for _, opt := range st.Raw.Options {
		if h, ok := Lookup(opt.Key); ok {
			if err := h.Handle(st, opt); err != nil {
				return fmt.Errorf("suricata: option %q: %w", opt.Key, err)
			}
			continue
		}
		st.Unsupported[opt.Key]++
	}
	return nil
}

// mapProto 把 Suricata 头部协议字符串映射为 IR 协议常量。
//
// tcp/udp/icmp/http/dns/tls/ssh 分别返回对应的 rule.Proto* 常量；
// 其它取值或空字符串返回 rule.ProtoAny。
func mapProto(s string) rule.Protocol {
	switch s {
	case "tcp":
		return rule.ProtoTCP
	case "udp":
		return rule.ProtoUDP
	case "icmp":
		return rule.ProtoICMP
	case "http":
		return rule.ProtoHTTP
	case "dns":
		return rule.ProtoDNS
	case "tls":
		return rule.ProtoTLS
	case "ssh":
		return rule.ProtoSSH
	default:
		return rule.ProtoAny
	}
}

// parseNetSpec 把地址字段解析为 rule.NetSpec。
//
// 规则：TrimSpace；以 '!' 开头则 Negate=true 并去掉该字符；随后若为 "any"
// 或为空则返回零值（不限定）；若被一对 [ ] 包裹则去掉最外层方括号；
// 最后按 ',' 拆分，每项 TrimSpace，非空项追加进 Networks。
// $HOME_NET 这类变量名原样保留，不做校验。
func parseNetSpec(s string) rule.NetSpec {
	s = strings.TrimSpace(s)

	var negate bool
	if strings.HasPrefix(s, "!") {
		negate = true
		s = strings.TrimSpace(s[1:])
	}

	if s == "" || s == "any" {
		return rule.NetSpec{}
	}

	if len(s) >= 2 && strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}

	ns := rule.NetSpec{Negate: negate}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ns.Networks = append(ns.Networks, part)
	}
	return ns
}

// parsePortSpec 把端口字段解析为 rule.PortSpec。
//
// 规则：TrimSpace；以 '!' 开头时返回 rule.PortSpec{Any: true}（P0 暂不支持
// 端口取反）；等于 "any" 或为空时同样返回 rule.PortSpec{Any: true}；
// 去掉最外层 [ ] 后按 ',' 拆分：含 ':' 的项拆成 From/To 并用 strconv.Atoi
// 解析后追加进 Ranges（任一侧解析失败则跳过该项）；否则按单端口解析后
// 追加进 Ports（解析失败则跳过该项）。
func parsePortSpec(s string) rule.PortSpec {
	s = strings.TrimSpace(s)

	if strings.HasPrefix(s, "!") {
		return rule.PortSpec{Any: true}
	}
	if s == "" || s == "any" {
		return rule.PortSpec{Any: true}
	}

	if len(s) >= 2 && strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}

	ps := rule.PortSpec{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, ":") {
			fields := strings.SplitN(part, ":", 2)
			from, errFrom := strconv.Atoi(strings.TrimSpace(fields[0]))
			to, errTo := strconv.Atoi(strings.TrimSpace(fields[1]))
			if errFrom != nil || errTo != nil {
				continue
			}
			ps.Ranges = append(ps.Ranges, rule.PortRange{
				From: uint16(from),
				To:   uint16(to),
			})
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		ps.Ports = append(ps.Ports, uint16(p))
	}
	return ps
}
