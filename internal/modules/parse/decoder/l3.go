package decoder

import (
	"fmt"
	"net"
)

// ip4 解析 IPv4 头（对应 PacketLens ip4() index.html:2309）。
func ip4(c *ctx, off, end int) {
	if end-off < 20 {
		c.proto("IPv4")
		c.info("IPv4 头不足 20 字节")
		return
	}

	vihl := c.byte(off)
	ihl := int(vihl&0x0f) * 4
	if ihl < 20 || ihl > 60 {
		c.proto("IPv4")
		c.info("IPv4 头长异常")
		return
	}
	tos := c.byte(off + 1)
	totalLen := c.u16(off + 2)
	id := c.u16(off + 4)
	ff := c.u16(off + 6)
	flags := ff >> 13
	fragOff := int(ff&0x1fff) * 8
	ttl := c.byte(off + 8)
	proto := c.byte(off + 9)

	srcIP := ip4String(c.b[off+12 : off+16])
	dstIP := ip4String(c.b[off+16 : off+20])

	p := c.p
	p.IPVersion = 4
	p.SrcIP = srcIP
	p.DstIP = dstIP
	p.Src = srcIP
	p.Dst = dstIP
	p.TTL = ttl
	p.IPProto = proto
	p.IPLen = int(totalLen)
	p.IPID = id
	p.SrcIPNum = c.u32(off + 12)
	p.DstIPNum = c.u32(off + 16)
	p.DF = flags&2 != 0
	p.MF = flags&1 != 0
	p.FragOff = fragOff

	c.layer("ip4")
	_ = tos

	// 分片处理（对应 PacketLens 2356-2363）
	if p.MF || fragOff > 0 {
		p.Fragmented = true
		if fragOff > 0 {
			c.proto("ipv4_frag")
			c.info(fmt.Sprintf("IP 分片 (offset=%d, id=0x%x)，未重组", fragOff, id))
			return
		}
	}

	// 载荷终点：totalLen 为 0 时用剩余长度
	payloadEnd := off + int(totalLen)
	if totalLen == 0 || payloadEnd > end {
		payloadEnd = end
	}
	if payloadEnd < off+ihl {
		payloadEnd = off + ihl
	}

	ipProtoDispatch(c, off+ihl, payloadEnd, proto)
}

// ip6 解析 IPv6 头 + 扩展头（对应 PacketLens ip6() index.html:2374）。
func ip6(c *ctx, off, end int) {
	if end-off < 40 {
		c.proto("IPv6")
		c.info("IPv6 头不足 40 字节")
		return
	}

	plen := c.u16(off + 4)
	nextHeader := c.byte(off + 6)
	hopLimit := c.byte(off + 7)

	srcIP := ip6String(c.b[off+8 : off+24])
	dstIP := ip6String(c.b[off+24 : off+40])

	p := c.p
	p.IPVersion = 6
	p.SrcIP = srcIP
	p.DstIP = dstIP
	p.Src = srcIP
	p.Dst = dstIP
	p.TTL = hopLimit
	p.IPProto = nextHeader
	p.IPLen = int(plen) + 40

	c.layer("ipv6")

	// 载荷终点
	payloadEnd := off + 40 + int(plen)
	if plen == 0 || payloadEnd > end {
		payloadEnd = end
	}

	// 扩展头循环（最多 8 层）
	o := off + 40
	guard := 0
	for guard < 8 && o < payloadEnd {
		guard++
		switch nextHeader {
		case 0, 43, 60, 51, 135: // hop-by-hop / routing / dest-opt / AH / mobility
			if o+2 > payloadEnd {
				break
			}
			var hlen int
			if nextHeader == 51 { // AH: (len+2)*4
				hlen = (int(c.b[o+1]) + 2) * 4
			} else { // 其他: (len+1)*8
				hlen = (int(c.b[o+1]) + 1) * 8
			}
			nextHeader = c.b[o]
			c.layer("ip6ext")
			o += hlen
			continue
		case 44: // fragment
			if o+8 > payloadEnd {
				break
			}
			fragOff6 := int(c.u16(o+2)>>3) * 8
			moreFrag := c.u16(o+2)&1 != 0
			p.Fragmented = true
			if fragOff6 > 0 {
				c.proto("IPv6 frag")
				c.info(fmt.Sprintf("IPv6 分片，offset=%d", fragOff6))
				return
			}
			_ = moreFrag
			nextHeader = c.b[o]
			c.layer("ip6frag")
			o += 8
			continue
		}
		break
	}

	p.IPProto = nextHeader
	ipProtoDispatch(c, o, payloadEnd, nextHeader)
}

// ipProtoDispatch 网络层协议分发（对应 PacketLens ipProto() index.html:2417）。
func ipProtoDispatch(c *ctx, off, end int, proto uint8) {
	switch proto {
	case 6:
		tcp(c, off, end)
	case 17:
		udp(c, off, end)
	case 1:
		icmp(c, off, end)
	case 58:
		icmp6(c, off, end)
	case 4:
		c.layer("ipip")
		ip4(c, off, end)
	case 41:
		c.layer("ip6in4")
		ip6(c, off, end)
	case 47:
		gre(c, off, end)
	default:
		c.proto(ipProtoName(proto))
		c.info(fmt.Sprintf("%s，载荷 %d 字节", ipProtoName(proto), end-off))
	}
}

// gre 解析 GRE 隧道（P0 简化：识别后按内层协议再分发）。
func gre(c *ctx, off, end int) {
	if end-off < 4 {
		return
	}
	protoType := c.u16(off + 2)
	c.layer("gre")
	c.info(fmt.Sprintf("GRE, protocol=0x%x", protoType))
	switch protoType {
	case 0x0800:
		ip4(c, off+4, end)
	case 0x86dd:
		ip6(c, off+4, end)
	}
}

// ip6String 格式化 IPv6（压缩表示）。
func ip6String(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return net.IP(b[:16]).String()
}
