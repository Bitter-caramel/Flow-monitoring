package l7

import (
	"encoding/binary"
	"fmt"

	"flow-monitoring/internal/kernel/datamodel"
)

// payload 返回应用层载荷切片。
func payload(p *datamodel.Packet) []byte {
	off := p.PayloadOff
	ln := p.PayloadLen
	if off < 0 || ln <= 0 || off+ln > len(p.Data) {
		return nil
	}
	return p.Data[off : off+ln]
}

// Dispatch 识别并解析 L7 协议。
//
// 前置条件：p 已完成 L4 解码（SrcPort/DstPort/IPProto/PayloadOff/PayloadLen 已填）。
// 载荷为空或无法识别时直接返回（保留 L4 的 proto 判定）。
func Dispatch(p *datamodel.Packet) {
	pl := payload(p)
	if len(pl) == 0 {
		return
	}
	isTCP := p.IPProto == 6

	if !isTCP {
		// UDP：端口优先
		sp, dp := p.SrcPort, p.DstPort
		switch {
		case dp == 53 || sp == 53 || dp == 5353 || sp == 5353 || dp == 5355 || sp == 5355:
			dns(p, pl)
			return
		case dp == 67 || dp == 68 || sp == 67 || sp == 68:
			dhcp(p, pl)
			return
		}
		return
	}

	// TCP：内容嗅探优先（对应 PacketLens dispatch 4016-4023）
	switch {
	case httpLike(pl) != 0:
		http(p, pl, httpLike(pl))
		return
	case isTLSRecord(pl):
		tls(p, pl)
		return
	case hasPrefix(pl, "SSH-"):
		p.Proto = "SSH"
		p.Info = "SSH banner"
		return
	}

	// TCP 端口兜底（仅当端口高度匹配时）
	sp, dp := p.SrcPort, p.DstPort
	if dp == 53 || sp == 53 {
		dns(p, pl)
	}
}

// u16be / u32be 大端读（网络字节序），越界返回 0（L7 解析容错）。
func u16be(b []byte, off int) uint16 {
	if off+2 > len(b) {
		return 0
	}
	return binary.BigEndian.Uint16(b[off:])
}

func u32be(b []byte, off int) uint32 {
	if off+4 > len(b) {
		return 0
	}
	return binary.BigEndian.Uint32(b[off:])
}

// hasPrefix 检查 b 从 off 开始是否以 prefix 开头。
func hasPrefix(b []byte, prefix string) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}

// hasPrefixAt 检查 b 从 off 开始是否以 prefix 开头。
func hasPrefixAt(b []byte, off int, prefix string) bool {
	if off < 0 || off+len(prefix) > len(b) {
		return false
	}
	return hasPrefix(b[off:], prefix)
}

// setInfo 设置包 INFO（若已有则追加）。
func setInfo(p *datamodel.Packet, s string) {
	if p.Info != "" {
		p.Info += " · " + s
	} else {
		p.Info = s
	}
}

var _ = fmt.Sprintf // 保留 fmt 引用（未来扩展用）
