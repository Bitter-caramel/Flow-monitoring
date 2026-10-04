package decoder

import (
	"fmt"

	"flow-monitoring/internal/kernel/datamodel"
)

// fallbackProto 兜底协议名：L4/L7 未识别时按 IP 协议号 / IP 版本 / EtherType 推断。
func fallbackProto(p *datamodel.Packet, linkType int) string {
	switch {
	case p.IPProto == 6:
		return "TCP"
	case p.IPProto == 17:
		return "UDP"
	case p.IPProto != 0:
		return ipProtoName(p.IPProto)
	case p.IPVersion == 4:
		return "IPv4"
	case p.IPVersion == 6:
		return "IPv6"
	case p.EtherType != 0:
		if name, ok := etherTypeName(p.EtherType); ok {
			return name
		}
		return fmt.Sprintf("EtherType-0x%x", p.EtherType)
	default:
		return fmt.Sprintf("LINK%d", linkType)
	}
}

// etherTypeName 返回 EtherType 的常见名称。
func etherTypeName(t uint16) (string, bool) {
	m := map[uint16]string{
		0x0800: "IPv4", 0x0806: "ARP", 0x8100: "802.1Q VLAN",
		0x86dd: "IPv6", 0x88a8: "802.1ad QinQ", 0x8847: "MPLS",
		0x8848: "MPLS multicast", 0x8863: "PPPoE Discovery",
		0x8864: "PPPoE Session", 0x888e: "EAPOL", 0x88cc: "LLDP",
	}
	name, ok := m[t]
	return name, ok
}

// ipProtoName 返回 IP 协议号名称。
func ipProtoName(pro uint8) string {
	m := map[uint8]string{
		1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6",
		47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF",
		132: "SCTP",
	}
	if name, ok := m[pro]; ok {
		return name
	}
	return fmt.Sprintf("IP-%d", pro)
}

// icmpTypeName 返回 ICMP 类型名。
func icmpTypeName(t uint8) string {
	m := map[uint8]string{
		0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
		5: "Redirect", 8: "Echo (ping) Request", 9: "Router Advertisement",
		10: "Router Solicitation", 11: "Time Exceeded", 12: "Parameter Problem",
		13: "Timestamp Request", 14: "Timestamp Reply",
	}
	if name, ok := m[t]; ok {
		return name
	}
	return fmt.Sprintf("Type %d", t)
}

// icmp6TypeName 返回 ICMPv6 类型名。
func icmp6TypeName(t uint8) string {
	m := map[uint8]string{
		1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded",
		128: "Echo Request", 129: "Echo Reply", 133: "Router Solicitation",
		134: "Router Advertisement", 135: "Neighbor Solicitation",
		136: "Neighbor Advertisement",
	}
	if name, ok := m[t]; ok {
		return name
	}
	return fmt.Sprintf("Type %d", t)
}
