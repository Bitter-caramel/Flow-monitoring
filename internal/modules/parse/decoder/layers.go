package decoder

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/modules/parse/decoder/l7"
)

// decode 按链路类型选择起始层解码，并把命中的层映射进 Packet。
//
// 支持的链路类型与原实现一致：Ethernet(1/279)、NULL loopback(0)、
// 裸 IP(12/14/101/228/229)；其余链路类型不做解码（交由上层兜底）。
func (d *decoders) decode(p *datamodel.Packet, linkType int, path *[]string) {
	var parser *gopacket.DecodingLayerParser
	data := p.Data

	switch linkType {
	case 1, 279: // Ethernet II
		parser = d.ethParser
	case 0: // BSD NULL loopback：4 字节地址族 + 内层 IP
		if len(data) < 4 {
			return
		}
		fam := binary.BigEndian.Uint32(data[:4])
		data = data[4:]
		*path = append(*path, "null")
		switch fam {
		case 2:
			parser = d.ip4Parser
		case 24, 28, 30:
			parser = d.ip6Parser
		default:
			return
		}
	case 12, 14, 101, 228, 229: // 裸 IP：按首字节版本号识别
		if len(data) == 0 {
			return
		}
		switch data[0] >> 4 {
		case 4:
			parser = d.ip4Parser
		case 6:
			parser = d.ip6Parser
		default:
			return
		}
	default:
		return
	}

	// gopacket 遇到未注册的层会返回错误，但此前已解出的层仍然有效，
	// 因此只有在"一层都没解出来"时才判定为畸形包。
	if err := parser.DecodeLayers(data, &d.decoded); err != nil && len(d.decoded) == 0 {
		p.Malformed = true
	}
	for _, lt := range d.decoded {
		d.apply(p, lt, path)
	}
}

// apply 把单个已解码层映射到 Packet。
//
// 只处理 decoded 里真实出现的层：DecodingLayerParser 复用层对象，
// 未出现的层会残留上一包的值，因此绝不能按固定顺序无条件读取。
func (d *decoders) apply(p *datamodel.Packet, lt gopacket.LayerType, path *[]string) {
	switch lt {
	case layers.LayerTypeEthernet:
		*path = append(*path, "eth")
		p.SrcMAC = d.eth.SrcMAC.String()
		p.DstMAC = d.eth.DstMAC.String()
		p.EtherType = uint16(d.eth.EthernetType)
		if d.eth.EthernetType < 0x0600 { // IEEE 802.3 长度字段（LLC），不再深入
			p.Info = fmt.Sprintf("802.3 LLC，长度 %d", d.eth.EthernetType)
		}
	case layers.LayerTypeDot1Q:
		*path = append(*path, "vlan")
		p.EtherType = uint16(d.dot1q.Type)
	case layers.LayerTypeARP:
		*path = append(*path, "arp")
		applyARP(p, &d.arp)
	case layers.LayerTypeIPv4:
		*path = append(*path, "ip4")
		applyIPv4(p, &d.ip4)
	case layers.LayerTypeIPv6:
		*path = append(*path, "ip6")
		applyIPv6(p, &d.ip6)
	case layers.LayerTypeTCP:
		*path = append(*path, "tcp")
		applyTCP(p, &d.tcp)
		if p.PayloadLen > 0 {
			l7.Dispatch(p) // TCP：内容嗅探优先
		}
	case layers.LayerTypeUDP:
		*path = append(*path, "udp")
		applyUDP(p, &d.udp)
		if p.PayloadLen > 0 {
			l7.Dispatch(p) // UDP：端口优先
		}
	case layers.LayerTypeICMPv4:
		*path = append(*path, "icmp")
		applyICMPv4(p, &d.icmp4)
	case layers.LayerTypeICMPv6:
		*path = append(*path, "icmpv6")
		applyICMPv6(p, &d.icmp6)
	}
}

// payloadOffset 计算载荷在 p.Data 中的绝对偏移。
//
// gopacket 的 Payload 是原始数据的后缀切片，故偏移 = 总长 - 载荷长。
func payloadOffset(p *datamodel.Packet, payload []byte) int {
	off := len(p.Data) - len(payload)
	if off < 0 {
		return 0
	}
	return off
}

// applyIPv4 映射 IPv4 层。
func applyIPv4(p *datamodel.Packet, ip *layers.IPv4) {
	p.IPVersion = 4
	p.SrcIP = ip.SrcIP.String()
	p.DstIP = ip.DstIP.String()
	p.Src = p.SrcIP
	p.Dst = p.DstIP
	p.SrcIPNum = ip4Num(ip.SrcIP)
	p.DstIPNum = ip4Num(ip.DstIP)
	p.TTL = ip.TTL
	p.IPProto = uint8(ip.Protocol)
	p.IPLen = int(ip.Length)
	p.IPID = ip.Id
	p.DF = ip.Flags&layers.IPv4DontFragment != 0
	p.MF = ip.Flags&layers.IPv4MoreFragments != 0
	p.FragOff = int(ip.FragOffset) * 8
	p.Fragmented = p.MF || p.FragOff > 0
}

// applyIPv6 映射 IPv6 层（IPv4 整数键留 0：Flow 目前只支持 IPv4）。
func applyIPv6(p *datamodel.Packet, ip *layers.IPv6) {
	p.IPVersion = 6
	p.SrcIP = ip.SrcIP.String()
	p.DstIP = ip.DstIP.String()
	p.Src = p.SrcIP
	p.Dst = p.DstIP
	p.SrcIPNum = 0
	p.DstIPNum = 0
	p.TTL = ip.HopLimit
	p.IPProto = uint8(ip.NextHeader)
	p.IPLen = int(ip.Length) + 40
}

// applyARP 映射 ARP/RARP 层。
func applyARP(p *datamodel.Packet, a *layers.ARP) {
	p.Proto = "ARP"
	p.Src = p.SrcMAC
	p.Dst = p.DstMAC

	senderIP, targetIP := ipString(a.SourceProtAddress), ipString(a.DstProtAddress)
	ar := &datamodel.ARP{
		Opcode:    a.Operation,
		SenderIP:  senderIP,
		SenderMAC: macString(a.SourceHwAddress),
		TargetIP:  targetIP,
		TargetMAC: macString(a.DstHwAddress),
	}
	p.ARP = ar

	switch a.Operation {
	case 1: // ARP request
		if senderIP != "" && senderIP == targetIP {
			ar.IsGratuitous = true
			p.Info = fmt.Sprintf("Gratuitous ARP: %s 声明自己 (%s)", senderIP, ar.SenderMAC)
		} else {
			p.Info = fmt.Sprintf("谁是 %s? 告诉 %s", targetIP, senderIP)
		}
	case 2: // ARP reply
		p.Info = fmt.Sprintf("%s 在 %s", senderIP, ar.SenderMAC)
	}
}

// ip4Num 把 IPv4 地址转成 uint32（用于流键）；非 IPv4 返回 0。
func ip4Num(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v4)
}

// ipString 把 4 字节地址转成点分十进制；长度不足返回空串。
func ipString(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	return net.IP(b[:4]).String()
}

// macString 格式化 MAC 地址。
func macString(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return net.HardwareAddr(b[:6]).String()
}
