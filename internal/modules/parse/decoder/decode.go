package decoder

import (
	"encoding/binary"
	"fmt"
	"strings"

	"flow-monitoring/internal/kernel/datamodel"
)

// ctx 解码上下文，持有当前包与原始字节。
//
// 对应 PacketLens Ctx（index.html:1536）的统计模式：
// 只做字段解析与 pathStr 拼接，不构建协议树。
type ctx struct {
	p    *datamodel.Packet
	b    []byte
	path []string // 协议路径（如 ["eth","ip4","tcp"]）
}

// proto 设置协议名并同步更新协议路径（对应 PacketLens Ctx.proto）。
func (c *ctx) proto(name string) {
	c.p.Proto = name
	if len(c.path) > 0 {
		c.path[len(c.path)-1] = strings.ToLower(name)
	} else {
		c.path = append(c.path, strings.ToLower(name))
	}
}

// info 设置 INFO 摘要。
func (c *ctx) info(s string) { c.p.Info = s }

// layer 追加一个协议层到路径（不覆盖 proto）。
func (c *ctx) layer(name string) {
	c.path = append(c.path, strings.ToLower(name))
}

// u16 大端读 16 位；越界 panic（由 Decode 的 recover 捕获）。
func (c *ctx) u16(off int) uint16 {
	if off+2 > len(c.b) {
		panic(fmt.Sprintf("read u16 @%d beyond %d", off, len(c.b)))
	}
	return binary.BigEndian.Uint16(c.b[off:])
}

// u32 大端读 32 位。
func (c *ctx) u32(off int) uint32 {
	if off+4 > len(c.b) {
		panic(fmt.Sprintf("read u32 @%d beyond %d", off, len(c.b)))
	}
	return binary.BigEndian.Uint32(c.b[off:])
}

// byte 读单字节。
func (c *ctx) byte(off int) byte {
	if off >= len(c.b) {
		panic(fmt.Sprintf("read byte @%d beyond %d", off, len(c.b)))
	}
	return c.b[off]
}

// slice 返回 [start,end) 切片；越界 panic。
func (c *ctx) slice(start, end int) []byte {
	if start < 0 || end > len(c.b) || start > end {
		panic(fmt.Sprintf("slice [%d,%d) beyond %d", start, end, len(c.b)))
	}
	return c.b[start:end]
}

// Decode 解码单个包，填充 datamodel.Packet 字段。
//
// linkType 来自该包所属接口（pcapng IDB 的 LinkType）。
// 解码异常不中断调用方：内部 panic 被 recover，包标记 Malformed。
//
// 对应 PacketLens decode()（index.html:1641）。
func Decode(p *datamodel.Packet, linkType int) {
	if p == nil || len(p.Data) == 0 {
		return
	}

	// 重置解码字段（支持同一包重复解码）
	p.Proto = ""
	p.Info = ""
	p.Src = ""
	p.Dst = ""
	p.SrcPort = 0
	p.DstPort = 0
	p.IPProto = 0
	p.TCPFlags = 0
	p.PayloadLen = 0
	p.PayloadOff = 0
	p.PathStr = ""
	p.Malformed = false

	// panic-recover 对应 PacketLens try/catch：单个畸形包不拖垮全量分析
	defer func() {
		if r := recover(); r != nil {
			p.Malformed = true
			if p.Info == "" {
				p.Info = fmt.Sprintf("[解码异常: %v]", r)
			}
		}
	}()

	c := &ctx{p: p, b: p.Data}
	link(c, 0, len(p.Data), linkType)

	// 兜底：无 src 时用 MAC（对应 PacketLens decode 兜底逻辑）
	if p.Src == "" {
		p.Src = p.SrcMAC
		p.Dst = p.DstMAC
	}

	// 兜底 proto（对应 PacketLens 1686-1708）
	if p.Proto == "" {
		p.Proto = fallbackProto(p, linkType)
		if p.Info == "" {
			p.Info = fmt.Sprintf("未进一步识别的 %s 数据，%d 字节", p.Proto, len(p.Data))
		}
	}

	if p.CapLen < p.OrigLen {
		p.Snapped = true
	}

	// 统计模式 pathStr：逗号包裹便于子串匹配
	p.PathStr = "," + strings.Join(c.path, ",") + ","
}

// fallbackProto 兜底协议名（对应 PacketLens 1686-1703）。
func fallbackProto(p *datamodel.Packet, linkType int) string {
	switch {
	case p.IPProto == 6:
		return "TCP"
	case p.IPProto == 17:
		return "UDP"
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

// link 链路类型分发（对应 PacketLens link() index.html:1828）。
//
// P0 支持：Ethernet(1/279)、NULL loopback(0)、raw IP(12/14/101)、
// IPv4/IPv6 直连(228/229)；其余回退 raw。
func link(c *ctx, off, end, linkType int) {
	c.layer("frame")
	switch linkType {
	case 1, 279:
		eth(c, off, end)
	case 0: // BSD NULL loopback
		if end-off < 4 {
			return
		}
		fam := c.u32(off) // 大端读（对应 PacketLens 取较小值逻辑，简化按 BE）
		c.layer("null")
		if fam == 2 {
			ip4(c, off+4, end)
		} else if fam == 24 || fam == 28 || fam == 30 {
			ip6(c, off+4, end)
		}
	case 12, 14, 101, 228, 229:
		// raw IP：按首字节版本识别
		ver := c.byte(off) >> 4
		if ver == 4 {
			ip4(c, off, end)
		} else if ver == 6 {
			ip6(c, off, end)
		} else {
			c.proto(fmt.Sprintf("LINK%d", linkType))
		}
	default:
		c.proto(fmt.Sprintf("LINK%d", linkType))
		c.info(fmt.Sprintf("未解码的链路层，%d 字节原始数据", end-off))
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
