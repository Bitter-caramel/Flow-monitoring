package decoder

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/gopacket/gopacket/layers"

	"flow-monitoring/internal/kernel/datamodel"
)

// applyTCP 映射 TCP 层。
func applyTCP(p *datamodel.Packet, t *layers.TCP, payloadOff int) {
	p.SrcPort = uint16(t.SrcPort)
	p.DstPort = uint16(t.DstPort)
	p.IPProto = 6
	p.TCPFlags = tcpFlags(t)
	// ★ 载荷起点由调用方按「头部长度累加」算好（帧尾填充不影响它）。
	p.PayloadOff = clampPayloadOff(payloadOff, len(p.Data))
	p.PayloadLen = len(t.Payload)
	p.Proto = "TCP"

	info := fmt.Sprintf("%d → %d [%s] Seq=%d", p.SrcPort, p.DstPort, tcpFlagString(p.TCPFlags), t.Seq)
	if t.ACK {
		info += fmt.Sprintf(" Ack=%d", t.Ack)
	}
	info += fmt.Sprintf(" Win=%d Len=%d", t.Window, p.PayloadLen)
	if opt := tcpOptionString(t); opt != "" {
		info += " " + opt
	}
	p.Info = info
}

// applyUDP 映射 UDP 层。
func applyUDP(p *datamodel.Packet, u *layers.UDP, payloadOff int) {
	p.SrcPort = uint16(u.SrcPort)
	p.DstPort = uint16(u.DstPort)
	p.IPProto = 17
	p.PayloadOff = clampPayloadOff(payloadOff, len(p.Data))
	p.PayloadLen = len(u.Payload)
	p.Proto = "UDP"
	p.Info = fmt.Sprintf("%d → %d Len=%d", p.SrcPort, p.DstPort, p.PayloadLen)
}

// clampPayloadOff 兜住越界：偏移必须落在 [0, n] 内，否则归 0。
//
// ★ 截断帧（snaplen）或畸形帧可能让「头部长度累加」的结果超过 len(Data)，
// 这里只保证不越界；载荷本身是否完整由 PayloadLen 与提取器的越界检查负责。
func clampPayloadOff(off, n int) int {
	if off < 0 || off > n {
		return 0
	}
	return off
}

// applyICMPv4 映射 ICMPv4 层。
func applyICMPv4(p *datamodel.Packet, ic *layers.ICMPv4) {
	t, c := ic.TypeCode.Type(), ic.TypeCode.Code()
	p.IPProto = 1
	p.Proto = "ICMP"
	p.ICMP = &datamodel.ICMP{
		Type:         t,
		Code:         c,
		Checksum:     ic.Checksum,
		DestUnreach:  t == 3,
		TimeExceeded: t == 11,
	}
	name := icmpTypeName(t)
	switch t { // 带 id/seq 的查询类报文
	case 0, 8, 13, 14, 15, 16, 17, 18:
		p.ICMP.ID = ic.Id
		p.ICMP.Seq = ic.Seq
		p.Info = fmt.Sprintf("%s id=0x%x, seq=%d, ttl=%d", name, ic.Id, ic.Seq, p.TTL)
	default:
		p.Info = name
	}
}

// applyICMPv6 映射 ICMPv6 层。
func applyICMPv6(p *datamodel.Packet, ic *layers.ICMPv6) {
	p.IPProto = 58
	p.Proto = "ICMPv6"
	p.ICMP = &datamodel.ICMP{Type: ic.TypeCode.Type(), Code: ic.TypeCode.Code()}
	p.Info = icmp6TypeName(p.ICMP.Type)
}

// tcpFlags 把 gopacket 的布尔标志拼成 datamodel 的 uint16 位掩码。
func tcpFlags(t *layers.TCP) uint16 {
	var f uint16
	if t.FIN {
		f |= tfFIN
	}
	if t.SYN {
		f |= tfSYN
	}
	if t.RST {
		f |= tfRST
	}
	if t.PSH {
		f |= tfPSH
	}
	if t.ACK {
		f |= tfACK
	}
	if t.URG {
		f |= tfURG
	}
	if t.ECE {
		f |= tfECE
	}
	if t.CWR {
		f |= tfCWR
	}
	return f
}

// tcpFlagString 生成 TCP 标志字符串（如 "SYN, ACK"）。
func tcpFlagString(f uint16) string {
	var a []string
	for _, x := range []struct {
		bit  uint16
		name string
	}{
		{tfCWR, "CWR"}, {tfECE, "ECE"}, {tfURG, "URG"}, {tfACK, "ACK"},
		{tfPSH, "PSH"}, {tfRST, "RST"}, {tfSYN, "SYN"}, {tfFIN, "FIN"},
	} {
		if f&x.bit != 0 {
			a = append(a, x.name)
		}
	}
	if len(a) == 0 {
		return "NONE"
	}
	return strings.Join(a, ", ")
}

// tcpOptionString 生成常见 TCP 选项摘要（MSS/WS/SACK/TS）。
func tcpOptionString(t *layers.TCP) string {
	var a []string
	for _, o := range t.Options {
		switch o.OptionType {
		case layers.TCPOptionKindMSS:
			if len(o.OptionData) >= 2 {
				a = append(a, fmt.Sprintf("MSS=%d", binary.BigEndian.Uint16(o.OptionData)))
			}
		case layers.TCPOptionKindWindowScale:
			if len(o.OptionData) >= 1 {
				a = append(a, fmt.Sprintf("WS=%d", 1<<o.OptionData[0]))
			}
		case layers.TCPOptionKindSACKPermitted:
			a = append(a, "SACK_PERM")
		case layers.TCPOptionKindTimestamps:
			if len(o.OptionData) >= 4 {
				a = append(a, fmt.Sprintf("TSval=%d", binary.BigEndian.Uint32(o.OptionData)))
			}
		}
	}
	return strings.Join(a, " ")
}
