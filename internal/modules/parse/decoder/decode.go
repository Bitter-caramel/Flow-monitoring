package decoder

import (
	"fmt"
	"strings"
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"flow-monitoring/internal/kernel/datamodel"
)

// TCP 标志位（与 datamodel.Packet.TCPFlags 的位约定一致）。
const (
	tfFIN uint16 = 0x01
	tfSYN uint16 = 0x02
	tfRST uint16 = 0x04
	tfPSH uint16 = 0x08
	tfACK uint16 = 0x10
	tfURG uint16 = 0x20
	tfECE uint16 = 0x40
	tfCWR uint16 = 0x80
)

// decoders 一包解码所需的全套 gopacket 层对象。
//
// 通过 sync.Pool 复用，避免逐包分配（解码位于热路径）。
// 同一 decoders 内的多个 parser 共享同一组层对象：每包只会走其中一个
// parser，且 apply 只读取 decoded 中真实出现的层，故互不干扰。
type decoders struct {
	eth     layers.Ethernet
	dot1q   layers.Dot1Q
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	icmp4   layers.ICMPv4
	icmp6   layers.ICMPv6
	arp     layers.ARP
	payload gopacket.Payload

	// hdrOff 是「本包已消费的头部长度」累计值，供 apply 计算 L4 载荷起点。
	hdrOff int

	ethParser *gopacket.DecodingLayerParser // 起始层 Ethernet
	ip4Parser *gopacket.DecodingLayerParser // 起始层 IPv4（裸 IP / NULL loopback）
	ip6Parser *gopacket.DecodingLayerParser // 起始层 IPv6

	decoded []gopacket.LayerType
}

var pool = sync.Pool{New: func() any {
	d := &decoders{}
	d.ethParser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&d.eth, &d.dot1q, &d.ip4, &d.ip6, &d.tcp, &d.udp, &d.icmp4, &d.icmp6, &d.arp, &d.payload)
	d.ip4Parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4,
		&d.ip4, &d.ip6, &d.tcp, &d.udp, &d.icmp4, &d.payload)
	d.ip6Parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6,
		&d.ip6, &d.ip4, &d.tcp, &d.udp, &d.icmp6, &d.payload)
	d.decoded = make([]gopacket.LayerType, 0, 12)
	return d
}}

// Decode 解码单个包，填充 datamodel.Packet 字段。
//
// linkType 来自该包所属接口（pcapng IDB 的 LinkType）。
// 解码异常不中断调用方：内部 panic 被 recover，包标记 Malformed。
//
// 解码本身由 gopacket 承担（见 docs/定制化与检测规划.md §2）：
// 协议解码是"苦力活"，复用社区实现可保证解码结果与社区标准一致，
// 不污染下游的流聚合与检测。
func Decode(p *datamodel.Packet, linkType int) {
	if p == nil || len(p.Data) == 0 {
		return
	}

	resetPacket(p)

	// panic-recover：单个畸形包不拖垮全量分析
	defer func() {
		if r := recover(); r != nil {
			p.Malformed = true
			if p.Info == "" {
				p.Info = fmt.Sprintf("[解码异常: %v]", r)
			}
		}
	}()

	path := make([]string, 0, 8)
	d := pool.Get().(*decoders)
	d.decode(p, linkType, &path)
	pool.Put(d)

	// 兜底：无 src 时用 MAC
	if p.Src == "" {
		p.Src = p.SrcMAC
		p.Dst = p.DstMAC
	}

	// 兜底 proto
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
	p.PathStr = "," + strings.Join(path, ",") + ","
}

// resetPacket 复位解码字段（支持同一包重复解码）。
func resetPacket(p *datamodel.Packet) {
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
}
