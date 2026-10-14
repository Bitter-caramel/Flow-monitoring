package reassembly

import (
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"
)

// StreamView 与 detect.StreamView 形状一致：
// 返回某条流两个方向「已重组」的字节。
//
// nil 语义与 detect 既有 Extractor 一致：数据不存在（无流 / 该方向为空）返回 nil，
// 表示「缓冲区不存在」，不是「空缓冲区」。绝不 panic。
//
// ★ 返回的是内部缓冲的切片快照，调用方只读、不得改写。
// 不复制：与 docs/TCP重组.md §5 一致，视图生命周期由 Reassembler 负责；
// 检测在上层「Feed 之后、下次 Feed 之前」同步消费，不存在并发改写窗口。
type StreamView interface {
	BytesToServer() []byte
	BytesToClient() []byte
}

// emptyStreamView 是「没有流数据」时的视图：两个方法都返回 nil。
type emptyStreamView struct{}

func (emptyStreamView) BytesToServer() []byte { return nil }
func (emptyStreamView) BytesToClient() []byte { return nil }

// streamView 是 Reassembler 返回给检测引擎的只读视图。
type streamView struct{ s *stream }

func (v *streamView) BytesToServer() []byte {
	if v == nil || v.s == nil {
		return nil
	}
	return nonEmpty(v.s.buf[ToServer])
}

func (v *streamView) BytesToClient() []byte {
	if v == nil || v.s == nil {
		return nil
	}
	return nonEmpty(v.s.buf[ToClient])
}

// nonEmpty 把空切片折叠成 nil，保持「nil = 不存在」的语义。
func nonEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

// stream 实现 gopacket 的 reassembly.Stream：
// 把 gopacket 交付的、按序重组后的字节存进两个方向缓冲。
//
// 缓冲下标 = 归一化方向（0=A→B，1=B→A），与 detect 的 StreamDir 对齐。
type stream struct {
	r          *Reassembler
	key        streamKey
	buf        [2][]byte
	stats      [2]StreamStats
	g2n        [2]uint8 // gopacket 方向(0=ClientToServer,1=ServerToClient) -> 归一化方向
	lastActive time.Time
	evicted    bool
	streamID   int
}

// Accept 接受所有 TCP 段。
//
// 对没有看到 SYN 的中途流也强制 start（*start = true），
// 这样单测/热路径即便只喂数据段也能建立流；真实握手流程同样兼容。
func (s *stream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	if start != nil {
		*start = true
	}
	return true
}

// ReassembledSG 收到一段已重组成序的数据：追加进对应方向缓冲，并如实记账。
//
// 洞的记法：用 gopacket 在 Info() 给出的 skip（本次跳过的缺失字节数）累加；
// 拿不到就记 0 —— 不假装完整（docs/TCP重组.md §7）。
func (s *stream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, _, _, skip := sg.Info()
	nd := s.g2n[dirIndex(dir)]
	if skip > 0 {
		s.stats[nd].Gaps++
		s.stats[nd].GapBytes += int64(skip)
	}
	if s.evicted {
		return
	}
	n, _ := sg.Lengths()
	if n <= 0 {
		return
	}
	data := sg.Fetch(n)
	if len(data) == 0 {
		return
	}
	s.r.appendData(s, nd, data)
}

// ReassemblyComplete 在 FIN/RST 或超时回收时被调用；返回 true 表示可从池中移除。
func (s *stream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	return true
}

// dirIndex 把 gopacket 的方向（bool）转成 0/1 下标。
func dirIndex(d reassembly.TCPFlowDirection) uint8 {
	if bool(d) {
		return 1
	}
	return 0
}

// streamFactory 由 gopacket 在发现新流时调用，创建我们的 stream。
type streamFactory struct{ r *Reassembler }

func (f streamFactory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	key, nd := keyFrom(netFlow.Src().Raw(), netFlow.Dst().Raw(), uint16(tcp.SrcPort), uint16(tcp.DstPort))
	s := &stream{
		r:          f.r,
		key:        key,
		lastActive: time.Now(),
		streamID:   -1,
	}
	// 触发本流创建的首包，其 gopacket 方向恒为 ClientToServer；
	// 它的归一化方向 nd 就是 ClientToServer 对应的方向。
	s.g2n[0] = nd
	s.g2n[1] = 1 - nd
	if f.r != nil && f.r.byKey != nil {
		f.r.byKey[key] = s
	}
	return s
}
