package decoder

import (
	"fmt"
	"net"

	"flow-monitoring/internal/kernel/datamodel"
)

// eth 解析 Ethernet II 帧（对应 PacketLens eth() index.html:2066）。
func eth(c *ctx, off, end int) {
	if end-off < 14 {
		// 帧不足 14 字节，尝试按 raw IP 回退
		if ver := validIPVersion(c, off, end); ver != 0 {
			rawIP(c, off, end, ver)
			return
		}
		c.proto("截断的以太网帧")
		return
	}

	dstMAC := macString(c.b[off : off+6])
	srcMAC := macString(c.b[off+6 : off+12])
	etherType := c.u16(off + 12)

	c.p.SrcMAC = srcMAC
	c.p.DstMAC = dstMAC
	c.p.EtherType = etherType

	c.layer("eth")

	if etherType <= 1500 {
		// IEEE 802.3 长度字段（LLC），P0 简化：不再深入
		c.info(fmt.Sprintf("802.3 LLC，长度 %d", etherType))
		return
	}

	etherPayload(c, off+14, end, etherType)
}

// validIPVersion 检查 offset 处是否为结构合法的 IPv4/IPv6（对应 validIpAt）。
// 返回 4/6/0。
func validIPVersion(c *ctx, off, end int) int {
	if off < 0 || off >= end {
		return 0
	}
	version := c.b[off] >> 4
	switch version {
	case 4:
		if end-off < 20 {
			return 0
		}
		ihl := int(c.b[off]&0x0f) * 4
		if ihl < 20 || ihl > 60 || off+ihl > end {
			return 0
		}
		return 4
	case 6:
		if end-off < 40 {
			return 0
		}
		return 6
	}
	return 0
}

// rawIP 按版本直接解析裸 IP。
func rawIP(c *ctx, off, end, version int) {
	if version == 4 {
		ip4(c, off, end)
	} else {
		ip6(c, off, end)
	}
}

// etherPayload 按 EtherType 分发（对应 PacketLens etherPayload() index.html:2208）。
func etherPayload(c *ctx, off, end int, etherType uint16) {
	switch etherType {
	case 0x0800: // IPv4
		ip4(c, off, end)
	case 0x86dd: // IPv6
		ip6(c, off, end)
	case 0x0806, 0x8035: // ARP / RARP
		arp(c, off, end, etherType)
	case 0x8100, 0x88a8, 0x9100: // VLAN
		if end-off < 4 {
			return
		}
		vlanID := c.u16(off) & 0x0fff
		innerType := c.u16(off + 2)
		c.layer("vlan")
		_ = vlanID // VLAN ID 暂不存储（datamodel 未预留），仅推进路径
		etherPayload(c, off+4, end, innerType)
	case 0x8847, 0x8848: // MPLS
		// P0 简化：解析标签栈后按内层 IP 版本分发
		o := off
		n := 0
		for o+4 <= end && n < 8 {
			label := c.u32(o) >> 12
			bos := c.b[o+2] & 1
			_ = label
			o += 4
			n++
			if bos != 0 {
				break
			}
		}
		c.layer("mpls")
		if o < end {
			if ver := c.b[o] >> 4; ver == 6 {
				ip6(c, o, end)
			} else if ver == 4 {
				ip4(c, o, end)
			}
		}
	default:
		if name, ok := etherTypeName(etherType); ok {
			c.proto(name)
		} else {
			c.proto(fmt.Sprintf("0x%x", etherType))
		}
		c.info(fmt.Sprintf("%s，载荷 %d 字节", c.p.Proto, end-off))
	}
}

// arp 解析 ARP 报文（对应 PacketLens arp() index.html:2285）。
func arp(c *ctx, off, end int, etherType uint16) {
	if end-off < 28 {
		c.proto("ARP")
		c.info("ARP 报文被截断")
		return
	}
	hwType := c.u16(off)
	protoType := c.u16(off + 2)
	hwLen := c.byte(off + 4)
	protoLen := c.byte(off + 5)
	opcode := c.u16(off + 6)

	senderMAC := macString(c.b[off+8 : off+8+int(hwLen)])
	targetMAC := macString(c.b[off+18 : off+18+int(hwLen)])

	var senderIP, targetIP string
	if protoLen == 4 {
		senderIP = ip4String(c.b[off+14 : off+18])
		targetIP = ip4String(c.b[off+24 : off+28])
	}

	c.layer("arp")
	c.p.ARP = &datamodel.ARP{
		Opcode:    opcode,
		SenderIP:  senderIP,
		SenderMAC: senderMAC,
		TargetIP:  targetIP,
		TargetMAC: targetMAC,
	}

	_ = hwType
	_ = protoType

	c.p.Src = c.p.SrcMAC
	c.p.Dst = c.p.DstMAC

	if etherType == 0x8035 {
		c.proto("RARP")
	} else {
		c.proto("ARP")
	}

	if opcode == 1 {
		if senderIP != "" && senderIP == targetIP {
			c.p.ARP.IsGratuitous = true
			c.info(fmt.Sprintf("Gratuitous ARP: %s 声明自己 (%s)", senderIP, senderMAC))
		} else {
			c.info(fmt.Sprintf("谁是 %s? 告诉 %s", targetIP, senderIP))
		}
	} else if opcode == 2 {
		c.info(fmt.Sprintf("%s 在 %s", senderIP, senderMAC))
	}
}

// macString 格式化 MAC 地址（无 net 依赖，直接用标准库）。
func macString(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return net.HardwareAddr(b[:6]).String()
}

// ip4String 点分十进制 IPv4。
func ip4String(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	return net.IP(b[:4]).String()
}
