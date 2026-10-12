package pcapng

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

// shbUserApplVal 是写入 SHB 的 shb_userappl 选项值（ASCII）。
//
// 注意：pcapng 规范与 reader.go 里 shb_userappl 的选项码是 4（reader.optUserAppl），
// 不是 3（3 是 shb_os）。为了让 reader 能把该值读回 Meta.App，这里用 optUserAppl。
const shbUserApplVal = "flow-monitoring"

// writerTimeUnitsPerSec 是 EPB 时间戳的分辨率：默认微秒（与 IDB 缺省 if_tsresol=6 一致）。
const writerTimeUnitsPerSec = 1_000_000

// Writer 把数据包写成 pcapng 流（写入调用方给的 io.Writer）。
type Writer struct {
	w        *bufio.Writer // 内部缓冲
	linkType uint16
	snaplen  uint32
	n        int64 // 已产出的逻辑字节数
	closed   bool
	err      error
}

// NewWriter 创建 Writer。linkType 为链路类型（1 = Ethernet）；snaplen 为每包最多写入的字节数（0 = 不限）。
// 构造时立刻写出 Section Header Block（含 shb_userappl 选项）与 Interface Description Block。
func NewWriter(w io.Writer, linkType int, snaplen int) (*Writer, error) {
	if w == nil {
		return nil, errors.New("pcapng: nil io.Writer")
	}
	if linkType < 0 {
		linkType = 0
	}
	if snaplen < 0 {
		snaplen = 0
	}
	wr := &Writer{
		w:        bufio.NewWriter(w),
		linkType: uint16(linkType),
		snaplen:  uint32(snaplen),
	}
	if err := wr.writeSHB(); err != nil {
		return nil, err
	}
	if err := wr.writeIDB(); err != nil {
		return nil, err
	}
	return wr, nil
}

// write 把 p 写入内部缓冲并累计逻辑字节数。
func (wr *Writer) write(p []byte) error {
	if wr.err != nil {
		return wr.err
	}
	n, err := wr.w.Write(p)
	wr.n += int64(n)
	if err != nil {
		wr.err = err
	}
	return err
}

// writeBlock 写一个完整块：块类型(4) + 块总长度(4) + 块体 + 块总长度(4)。
// body 必须已按 4 字节对齐（长度字段含 padding），否则返回错误。
func (wr *Writer) writeBlock(blockType uint32, body []byte) error {
	if len(body)%4 != 0 {
		return errors.New("pcapng: block body not 4-byte aligned")
	}
	total := uint32(len(body) + 12)
	var buf [12]byte
	binary.LittleEndian.PutUint32(buf[0:4], blockType)
	binary.LittleEndian.PutUint32(buf[4:8], total)
	binary.LittleEndian.PutUint32(buf[8:12], total)
	if err := wr.write(buf[0:8]); err != nil {
		return err
	}
	if err := wr.write(body); err != nil {
		return err
	}
	return wr.write(buf[8:12])
}

// appendOption 追加一个 pcapng 选项：选项码(2) + 长度(2) + 值 + padding 到 4 字节。
func appendOption(dst []byte, code uint16, val []byte) []byte {
	var hdr [4]byte
	binary.LittleEndian.PutUint16(hdr[0:2], code)
	binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(val)))
	dst = append(dst, hdr[:]...)
	dst = append(dst, val...)
	if pad := (4 - len(val)%4) % 4; pad > 0 {
		dst = append(dst, make([]byte, pad)...)
	}
	return dst
}

// appendEndOfOpt 追加 opt_endofopt（选项码 0，长度 0）。
func appendEndOfOpt(dst []byte) []byte {
	return append(dst, 0, 0, 0, 0)
}

// writeSHB 写出 Section Header Block。
func (wr *Writer) writeSHB() error {
	body := make([]byte, 0, 64)
	var hdr [16]byte
	binary.LittleEndian.PutUint32(hdr[0:4], 0x1A2B3C4D)          // 字节序魔数
	binary.LittleEndian.PutUint16(hdr[4:6], 1)                   // 主版本
	binary.LittleEndian.PutUint16(hdr[6:8], 0)                   // 次版本
	binary.LittleEndian.PutUint64(hdr[8:16], 0xFFFFFFFFFFFFFFFF) // 段长度未知
	body = append(body, hdr[:]...)
	// shb_userappl（选项码 = reader.optUserAppl）
	body = appendOption(body, optUserAppl, []byte(shbUserApplVal))
	body = appendEndOfOpt(body)
	return wr.writeBlock(blockSHB, body)
}

// writeIDB 写出 Interface Description Block。
func (wr *Writer) writeIDB() error {
	body := make([]byte, 0, 16)
	var hdr [8]byte
	binary.LittleEndian.PutUint16(hdr[0:2], wr.linkType) // LinkType
	binary.LittleEndian.PutUint16(hdr[2:4], 0)           // 保留
	binary.LittleEndian.PutUint32(hdr[4:8], wr.snaplen)  // SnapLen
	body = append(body, hdr[:]...)
	body = appendEndOfOpt(body)
	return wr.writeBlock(blockIDB, body)
}

// WritePacket 写入一个包：ts 为包时间（零值表示时间未知，写 0）；data 为原始帧字节。
// 必须按 pcapng 规范做 4 字节对齐填充，且每个块的长度字段包含填充。
func (wr *Writer) WritePacket(ts time.Time, data []byte) error {
	if wr.closed {
		return errors.New("pcapng: WritePacket on closed writer")
	}

	capData := data
	if wr.snaplen > 0 && uint64(len(data)) > uint64(wr.snaplen) {
		capData = data[:wr.snaplen]
	}
	capLen := uint32(len(capData))
	origLen := uint32(len(data))

	// 时间戳：64 位微秒计数（高 32 位在前），与 IDB 缺省分辨率一致。
	var raw uint64
	if !ts.IsZero() {
		if us := ts.UnixMicro(); us > 0 {
			raw = uint64(us)
		}
	}

	body := make([]byte, 0, 20+len(capData)+8)
	var hdr [20]byte
	binary.LittleEndian.PutUint32(hdr[0:4], 0)               // InterfaceID
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(raw>>32)) // 时间戳高位
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(raw))    // 时间戳低位
	binary.LittleEndian.PutUint32(hdr[12:16], capLen)        // 捕获长度
	binary.LittleEndian.PutUint32(hdr[16:20], origLen)       // 原始长度
	body = append(body, hdr[:]...)
	body = append(body, capData...)
	if pad := (4 - len(capData)%4) % 4; pad > 0 {
		body = append(body, make([]byte, pad)...)
	}
	body = appendEndOfOpt(body)
	return wr.writeBlock(blockEPB, body)
}

// BytesWritten 返回已写入底层的总字节数（供上层"写到阈值就封段"用）。
func (wr *Writer) BytesWritten() int64 { return wr.n }

// Flush 冲刷内部缓冲（不关闭底层 writer）。
func (wr *Writer) Flush() error {
	if wr.err != nil {
		return wr.err
	}
	return wr.w.Flush()
}

// Close 冲刷并释放（不关闭调用方传进来的 io.Writer）。
func (wr *Writer) Close() error {
	if wr.closed {
		return wr.err
	}
	wr.closed = true
	return wr.Flush()
}
