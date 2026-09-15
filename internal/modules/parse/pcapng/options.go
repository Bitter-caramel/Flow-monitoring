package pcapng

import "net"

// option 单个 pcapng 选项（code + 原始值切片）。
type option struct {
	code uint16
	val  []byte
}

// options 迭代 pcapng 选项区（对应 PacketLens opts() index.html:1096）。
//
// 选项结构：code(u16) + length(u16) + value(length 字节)，
// 每项 value 按 4 字节对齐 padding。
// 遇到 code==0（opt_endofopt）或越界时停止。
func (r *reader) options(start, end int) []option {
	var out []option
	s := start
	for s+4 <= end {
		code := r.bo.Uint16(r.data[s : s+2])
		ln := int(r.bo.Uint16(r.data[s+2 : s+4]))
		s += 4
		if code == optEnd {
			break
		}
		if s+ln > end {
			break
		}
		out = append(out, option{code: code, val: r.data[s : s+ln]})
		s += ln + ((4 - (ln % 4)) % 4)
	}
	return out
}

// text 把选项值转为字符串（Go 直接按字节序列保留，等价 PacketLens U.txt 的 UTF-8 解码）。
func text(b []byte) string {
	return string(b)
}

// ip4 点分十进制 IPv4。
func ip4(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	return net.IP(b[:4]).String()
}

// mac 冒号分隔的 MAC 地址。
func mac(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return net.HardwareAddr(b[:6]).String()
}
