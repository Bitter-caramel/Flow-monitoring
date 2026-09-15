package decoder

import (
	"fmt"
	"strings"

	"flow-monitoring/internal/kernel/datamodel"
)

// tcp 解析 TCP 头（对应 PacketLens tcp() index.html:2525）。
func tcp(c *ctx, off, end int) {
	if end-off < 20 {
		c.proto("TCP")
		c.info("TCP 头不足 20 字节")
		return
	}

	sp := c.u16(off)
	dp := c.u16(off + 2)
	seq := c.u32(off + 4)
	ack := c.u32(off + 8)
	dataOffset := int(c.byte(off+12)>>4) * 4
	if dataOffset < 20 {
		dataOffset = 20
	}
	// 标志位：bit8=NS(来自 data offset 字节的低 1 位)，bit0-7=标准标志
	flags := uint16(c.byte(off+12)&1)<<8 | uint16(c.byte(off+13))
	win := c.u16(off + 14)

	pl := end - off - dataOffset
	if pl < 0 {
		pl = 0
	}

	p := c.p
	p.SrcPort = sp
	p.DstPort = dp
	p.TCPFlags = flags
	p.PayloadLen = pl
	p.PayloadOff = off + dataOffset
	p.IPProto = 6

	c.layer("tcp")
	c.proto("TCP")

	// 解析常见 TCP 选项（MSS/WS/SACK/TS），存入 Info 摘要
	var optStr []string
	if dataOffset > 20 {
		oo := off + 20
		oe := off + dataOffset
		if oe > end {
			oe = end
		}
		for oo < oe {
			kind := c.byte(oo)
			if kind == 0 { // End of Option List
				break
			}
			if kind == 1 { // NOP
				oo++
				continue
			}
			if oo+1 >= oe {
				break
			}
			ln := int(c.byte(oo + 1))
			if ln < 2 || oo+ln > oe {
				break
			}
			switch kind {
			case 2: // MSS
				optStr = append(optStr, fmt.Sprintf("MSS=%d", c.u16(oo+2)))
			case 3: // Window Scale
				optStr = append(optStr, fmt.Sprintf("WS=%d", 1<<c.byte(oo+2)))
			case 4: // SACK Permitted
				optStr = append(optStr, "SACK_PERM")
			case 8: // Timestamps
				optStr = append(optStr, fmt.Sprintf("TSval=%d", c.u32(oo+2)))
			}
			oo += ln
		}
	}

	flagStr := tcpFlagString(flags)
	info := fmt.Sprintf("%d → %d [%s] Seq=%d", sp, dp, flagStr, seq)
	if flags&0x10 != 0 {
		info += fmt.Sprintf(" Ack=%d", ack)
	}
	info += fmt.Sprintf(" Win=%d Len=%d", win, pl)
	if len(optStr) > 0 {
		info += " " + strings.Join(optStr, " ")
	}
	c.info(info)

	// L7 分发（后续由 decoder/l7 实现；P0 暂留空，仅标记 payload 存在）
	if pl > 0 {
		// TODO(P2): dispatch(c, off+dataOffset, end, sp, dp, "tcp")
	}
}

// udp 解析 UDP 头（对应 PacketLens udp() index.html:2591）。
func udp(c *ctx, off, end int) {
	if end-off < 8 {
		c.proto("UDP")
		c.info("UDP 头不足 8 字节")
		return
	}

	sp := c.u16(off)
	dp := c.u16(off + 2)
	udpLen := c.u16(off + 4)

	payloadEnd := off + int(udpLen)
	if udpLen == 0 || payloadEnd > end {
		payloadEnd = end
	}
	pl := payloadEnd - off - 8
	if pl < 0 {
		pl = 0
	}

	p := c.p
	p.SrcPort = sp
	p.DstPort = dp
	p.PayloadLen = pl
	p.PayloadOff = off + 8
	p.IPProto = 17

	c.layer("udp")
	c.proto("UDP")
	c.info(fmt.Sprintf("%d → %d Len=%d", sp, dp, pl))

	// L7 分发（后续补充）
	if pl > 0 {
		// TODO(P2): dispatch(c, off+8, payloadEnd, sp, dp, "udp")
	}
}

// icmp 解析 ICMP 报文（对应 PacketLens icmp() index.html:2614）。
func icmp(c *ctx, off, end int) {
	if end-off < 4 {
		c.proto("ICMP")
		return
	}

	typ := c.byte(off)
	code := c.byte(off + 1)
	cksum := c.u16(off + 2)

	p := c.p
	p.IPProto = 1
	p.ICMP = &datamodel.ICMP{
		Type:         typ,
		Code:         code,
		Checksum:     cksum,
		DestUnreach:  typ == 3,
		TimeExceeded: typ == 11,
	}

	c.layer("icmp")
	c.proto("ICMP")

	name := icmpTypeName(typ)
	if typ == 8 || typ == 0 || typ == 13 || typ == 14 || typ == 15 || typ == 16 || typ == 17 || typ == 18 {
		id := c.u16(off + 4)
		sq := c.u16(off + 6)
		p.ICMP.ID = id
		p.ICMP.Seq = sq
		c.info(fmt.Sprintf("%s id=0x%x, seq=%d, ttl=%d", name, id, sq, p.TTL))
		return
	}
	c.info(name)
}

// icmp6 解析 ICMPv6 报文（P0 简化）。
func icmp6(c *ctx, off, end int) {
	if end-off < 4 {
		c.proto("ICMPv6")
		return
	}
	typ := c.byte(off)
	code := c.byte(off + 1)

	p := c.p
	p.IPProto = 58
	p.ICMP = &datamodel.ICMP{Type: typ, Code: code}

	c.layer("icmpv6")
	c.proto("ICMPv6")
	c.info(icmp6TypeName(typ))
}

// tcpFlagString 生成 TCP 标志位字符串（如 "SYN, ACK"）。
func tcpFlagString(flags uint16) string {
	var a []string
	if flags&0x100 != 0 {
		a = append(a, "NS")
	}
	if flags&0x80 != 0 {
		a = append(a, "CWR")
	}
	if flags&0x40 != 0 {
		a = append(a, "ECE")
	}
	if flags&0x20 != 0 {
		a = append(a, "URG")
	}
	if flags&0x10 != 0 {
		a = append(a, "ACK")
	}
	if flags&0x08 != 0 {
		a = append(a, "PSH")
	}
	if flags&0x04 != 0 {
		a = append(a, "RST")
	}
	if flags&0x02 != 0 {
		a = append(a, "SYN")
	}
	if flags&0x01 != 0 {
		a = append(a, "FIN")
	}
	if len(a) == 0 {
		return "NONE"
	}
	return strings.Join(a, ", ")
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
