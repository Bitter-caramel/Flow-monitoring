package pcapng

import (
	"encoding/binary"
	"fmt"
	"time"

	"flow-monitoring/internal/kernel/datamodel"
)

// 块类型常量（pcapng 规范）。
const (
	blockSHB = 0x0a0d0d0a // Section Header Block
	blockIDB = 0x00000001 // Interface Description Block
	blockEPB = 0x00000006 // Enhanced Packet Block
	blockSPB = 0x00000003 // Simple Packet Block（暂未实现）
	blockPB  = 0x00000002 // obsolete Packet Block（暂未实现）
	blockNRB = 0x00000004 // Name Resolution Block（暂未实现）
	blockISB = 0x00000005 // Interface Statistics Block（暂未实现）
	blockDSB = 0x0000000a // Decryption Secrets Block（暂未实现）
)

// 选项 code 常量（IDB/SHB 共用部分）。
const (
	optEnd         = 0
	optComment     = 1
	optHardware    = 2 // SHB
	optOS          = 3 // SHB
	optUserAppl    = 4 // SHB
	optIFName      = 2 // IDB
	optIFDesc      = 3 // IDB
	optIFIPv4      = 4 // IDB
	optIFMAC       = 6 // IDB
	optIFSpeed     = 8 // IDB
	optIFTSResol   = 9 // IDB
	optIFFilter    = 11 // IDB
	optIFOS        = 12 // IDB
	optIFTSOffset  = 14 // IDB
	optIFHardware  = 15 // IDB
	// EPB 包级选项
	optEpbComment = 1
	optEpbDir     = 2 // 方向：低 2 位，1=入 2=出
	optEpbPID     = 5 // 进程 ID
)

// defaultTSResol 默认时间戳分辨率：6 = 微秒（对应 tsscale 1e6）。
const defaultTSResol = 6

// reader 维护单次解析过程中的可变状态（字节序等）。
type reader struct {
	data []byte // 原始字节
	le   bool   // 当前 section 字节序（true=小端）
	bo   binary.ByteOrder
}

// Parse 解析 pcapng 数据，返回 Capture。
//
// limit 为最大解析包数；<=0 表示不限制。
// data 不会被拷贝，Capture.Raw 直接引用 data；Packet.Data 切片引用 Raw 区间。
func Parse(data []byte, limit int) (*datamodel.Capture, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("pcapng: data too short (%d bytes)", len(data))
	}
	r := &reader{data: data, le: true, bo: binary.LittleEndian}

	c := &datamodel.Capture{
		Format:   "pcapng",
		Endian:   "little",
		Packets:  []*datamodel.Packet{},
		Ifaces:   []datamodel.Interface{},
		Raw:      data,
		Kind:     "pcapng",
		NRB:      map[uint32]string{},
		Warns:    []string{},
		Stats:    []datamodel.InterfaceStat{},
	}

	off := 0
	no := 0
	for off+12 <= len(data) {
		// SHB 类型值 0x0A0D0D0A 字节序无关，先按 LE 试读
		blockType := binary.LittleEndian.Uint32(data[off : off+4])
		if blockType == blockSHB {
			// BOM 必须用大端读取：小端存储时字节为 4D 3C 2B 1A，
			// 大端读得 0x4D3C2B1A；大端存储时读得 0x1A2B3C4D。
			bom := binary.BigEndian.Uint32(data[off+8 : off+12])
			switch bom {
			case 0x4d3c2b1a:
				r.le = true
				r.bo = binary.LittleEndian
			case 0x1a2b3c4d:
				r.le = false
				r.bo = binary.BigEndian
			default:
				c.Warns = append(c.Warns, fmt.Sprintf("SHB 字节序标记异常 @0x%x", off))
			}
			c.Endian = map[bool]string{true: "little", false: "big"}[r.le]
			c.Sections++
		} else {
			blockType = r.bo.Uint32(data[off : off+4])
		}

		tlen := int(r.bo.Uint32(data[off+4 : off+8]))

		// 块长度校验
		if tlen < 12 || (tlen&3) != 0 || tlen > len(data)-off {
			c.Warns = append(c.Warns, fmt.Sprintf("块长度异常 (%d) @0x%x", tlen, off))
			break
		}
		// 首尾长度一致性
		tail := int(r.bo.Uint32(data[off+tlen-4 : off+tlen]))
		if tail != tlen {
			c.Warns = append(c.Warns, fmt.Sprintf("块首尾长度不一致 @0x%x (header=%d, trailer=%d)", off, tlen, tail))
			break
		}

		bodyStart := off + 8
		bodyEnd := off + tlen - 4

		// 最小块长校验
		minLen := minBlockLen(blockType)
		if tlen < minLen {
			c.Warns = append(c.Warns, fmt.Sprintf("pcapng 块过短 (%d < %d) @0x%x", tlen, minLen, off))
			off += tlen
			continue
		}

		switch blockType {
		case blockSHB:
			r.parseSHB(c, off, bodyEnd)
		case blockIDB:
			r.parseIDB(c, bodyStart, bodyEnd)
		case blockEPB:
			no = r.parseEPB(c, no, bodyStart, bodyEnd)
		case blockSPB, blockPB, blockNRB, blockISB, blockDSB:
			// 暂未实现：跳过（块边界已校验，直接前进）
		default:
			// 未知块：跳过
		}

		off += tlen
		if limit > 0 && no >= limit {
			c.Warns = append(c.Warns, fmt.Sprintf("已达到解析上限 %d 帧，其余帧未解析", limit))
			break
		}
	}

	// 兜底：无接口时补默认 Ethernet
	if len(c.Ifaces) == 0 {
		c.Ifaces = append(c.Ifaces, datamodel.Interface{ID: 0, LinkType: 1, SnapLen: 0, TSScale: datamodel.DefaultTSScale})
	}
	if c.LinkType == 0 {
		c.LinkType = c.Ifaces[0].LinkType
	}
	return c, nil
}

// minBlockLen 返回各块类型的最小长度（对应 PacketLens minBlock 表）。
func minBlockLen(t uint32) int {
	switch t {
	case blockSHB:
		return 28
	case blockIDB:
		return 20
	case blockEPB:
		return 32
	case blockSPB:
		return 16
	case blockPB:
		return 32
	case blockNRB:
		return 16
	case blockISB:
		return 24
	case blockDSB:
		return 20
	default:
		return 12
	}
}

// parseSHB 解析 Section Header Block。
func (r *reader) parseSHB(c *datamodel.Capture, off, bodyEnd int) {
	c.Version = fmt.Sprintf("%d.%d",
		r.bo.Uint16(r.data[off+12:off+14]),
		r.bo.Uint16(r.data[off+14:off+16]),
	)
	opts := r.options(off+24, bodyEnd)
	for _, o := range opts {
		switch o.code {
		case optComment:
			c.Comments = append(c.Comments, text(o.val))
		case optHardware:
			c.Meta.Hardware = text(o.val)
		case optOS:
			c.Meta.OS = text(o.val)
		case optUserAppl:
			c.Meta.App = text(o.val)
		}
	}
}

// parseIDB 解析 Interface Description Block。
func (r *reader) parseIDB(c *datamodel.Capture, bodyStart, bodyEnd int) {
	if bodyStart+8 > len(r.data) {
		return
	}
	ifc := datamodel.Interface{
		ID:       len(c.Ifaces),
		LinkType: int(r.bo.Uint16(r.data[bodyStart : bodyStart+2])),
		SnapLen:  int(r.bo.Uint32(r.data[bodyStart+4 : bodyStart+8])),
		TSScale:  datamodel.DefaultTSScale,
		TSResol:  uint8Ptr(defaultTSResol),
	}

	opts := r.options(bodyStart+8, bodyEnd)
	for _, o := range opts {
		switch o.code {
		case optIFName:
			ifc.Name = text(o.val)
		case optIFDesc:
			ifc.Desc = text(o.val)
		case optIFIPv4:
			if len(o.val) >= 8 {
				ifc.IPv4 = ip4(o.val[0:4]) + "/" + ip4(o.val[4:8])
			}
		case optIFMAC:
			if len(o.val) >= 6 {
				ifc.MAC = mac(o.val[0:6])
			}
		case optIFSpeed:
			if len(o.val) >= 8 {
				ifc.Speed = r.u64(o.val)
			}
		case optIFTSResol:
			if len(o.val) >= 1 {
				resol := o.val[0]
				ifc.TSResol = &resol
				ifc.TSScale = tsScale(resol)
			}
		case optIFFilter:
			if len(o.val) >= 1 {
				ifc.Filter = text(o.val[1:]) // 第一个字节是 null 分隔
			}
		case optIFOS:
			ifc.OS = text(o.val)
		case optIFHardware:
			ifc.Hardware = text(o.val)
		case optIFTSOffset:
			if len(o.val) >= 8 {
				ifc.TSOffset = int64(r.u64(o.val))
			}
		}
	}

	if c.LinkType == 0 {
		c.LinkType = ifc.LinkType
		c.SnapLen = ifc.SnapLen
	}
	c.Ifaces = append(c.Ifaces, ifc)
}

// parseEPB 解析 Enhanced Packet Block，返回新的包序号。
func (r *reader) parseEPB(c *datamodel.Capture, no, bodyStart, bodyEnd int) int {
	if bodyStart+20 > len(r.data) {
		return no
	}
	iid := int(r.bo.Uint32(r.data[bodyStart : bodyStart+4]))
	th := uint64(r.bo.Uint32(r.data[bodyStart+4 : bodyStart+8]))
	tl := uint64(r.bo.Uint32(r.data[bodyStart+8 : bodyStart+12]))
	capLen := int(r.bo.Uint32(r.data[bodyStart+12 : bodyStart+16]))
	origLen := int(r.bo.Uint32(r.data[bodyStart+16 : bodyStart+20]))

	// 接口回退：引用不存在的 ID 时用 ifaces[0] 或默认
	ifc := r.ifaceFor(c, iid)
	scale := ifc.TSScale
	if scale == 0 {
		scale = datamodel.DefaultTSScale
	}

	// 64 位时间戳合成
	raw := th<<32 | tl
	secs := int64(raw / uint64(scale))
	frac := float64(raw%uint64(scale)) / float64(scale)
	secs += ifc.TSOffset

	dataStart := bodyStart + 20
	dataEnd := dataStart + capLen
	if dataEnd > bodyEnd {
		c.Warns = append(c.Warns, fmt.Sprintf("pcapng 第 %d 帧的抓取长度超出块边界，已截断", no+1))
		dataEnd = bodyEnd
	}
	if dataEnd > len(r.data) {
		dataEnd = len(r.data)
	}
	if dataEnd < dataStart {
		dataEnd = dataStart
	}

	p := datamodel.NewPacket()
	p.No = no + 1
	p.Sec = secs
	p.Usec = int64(frac * 1e6) % 1_000_000
	p.Time = time.Unix(secs, int64(frac*1e9))
	p.CapLen = dataEnd - dataStart
	p.OrigLen = origLen
	if p.OrigLen == 0 {
		p.OrigLen = p.CapLen
	}
	p.Iface = iid
	p.Data = r.data[dataStart:dataEnd]
	p.DataOff = int64(dataStart)

	// 包级选项（EPB 数据区 4 字节对齐后）
	padded := bodyStart + 20 + capLen + ((4 - (capLen % 4)) % 4)
	if padded < bodyEnd {
		for _, o := range r.options(padded, bodyEnd) {
			switch o.code {
			case optEpbComment:
				p.Info = text(o.val) // 包注释暂放 Info（后续可扩展独立字段）
			case optEpbDir:
				if len(o.val) >= 4 {
					// dir 选项：低 2 位 1=入 2=出；当前 datamodel 未独立存储，忽略
				}
			case optEpbPID:
				// 进程 ID，暂忽略
			}
		}
	}

	c.Packets = append(c.Packets, p)
	return no + 1
}

// ifaceFor 返回接口；引用不存在 ID 时回退 ifaces[0] 或默认 Ethernet。
func (r *reader) ifaceFor(c *datamodel.Capture, iid int) datamodel.Interface {
	if iid >= 0 && iid < len(c.Ifaces) {
		return c.Ifaces[iid]
	}
	if len(c.Ifaces) > 0 {
		return c.Ifaces[0]
	}
	return datamodel.Interface{LinkType: 1, TSScale: datamodel.DefaultTSScale}
}

// u64 按当前 section 字节序读 64 位无符号整数。
func (r *reader) u64(b []byte) uint64 {
	if r.le {
		return uint64(binary.LittleEndian.Uint32(b[4:8]))<<32 |
			uint64(binary.LittleEndian.Uint32(b[0:4]))
	}
	return uint64(binary.BigEndian.Uint32(b[0:4]))<<32 |
		uint64(binary.BigEndian.Uint32(b[4:8]))
}

// tsScale 时间戳分辨率 → 缩放因子（对应 PacketLens tsScale）。
//
//	tsresol & 0x80 → 2^(tsresol & 0x7f)  二进制分辨率
//	否则           → 10^tsresol          十进制（0=秒,3=毫秒,6=微秒,9=纳秒）
func tsScale(tsresol uint8) float64 {
	if tsresol&0x80 != 0 {
		return float64(int(1) << (tsresol & 0x7f))
	}
	p := float64(1)
	for i := uint8(0); i < (tsresol & 0x7f); i++ {
		p *= 10
	}
	return p
}

// uint8Ptr 返回指向 v 的指针（datamodel.Interface.TSResol 为 *uint8）。
func uint8Ptr(v uint8) *uint8 { return &v }
