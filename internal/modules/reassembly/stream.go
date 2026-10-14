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
	// Midstream 报告「重组视图不可信」：这条流出现过落在重组基准之前的段
	// （中途抓包 + 乱序 ⇒ 这些段会永远搁浅，见 docs/TCP重组.md §7.3）。
	// 没有流（空视图）时返回 false。
	Midstream() bool
}

// emptyStreamView 是「没有流数据」时的视图：两个方法都返回 nil。
type emptyStreamView struct{}

func (emptyStreamView) BytesToServer() []byte { return nil }
func (emptyStreamView) BytesToClient() []byte { return nil }

// Midstream 恒为 false：★「没有流」不等于「中途流」，不能让它回落 payload。
func (emptyStreamView) Midstream() bool { return false }

// streamView 是 Reassembler 返回给检测引擎的只读视图。
type streamView struct {
	s *stream
	// midstream = s.unreliable（粘性，本流出现过搁浅段）|| r.preBaseline（仅本包）。
	midstream bool
}

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

// Midstream 返回视图构造时算出的不可信标记；nil 接收者按「无流」处理返回 false。
func (v *streamView) Midstream() bool {
	if v == nil {
		return false
	}
	return v.midstream
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

	// ── C′（窄口径防漏）的簿记 ──
	// baseline[d]：方向 d「首个观察段的基准候选」，等于 gopacket 给该 half 设的
	// nextSeq（首段带 SYN 时 = SYN.seq+1，对齐 tcpassembly.go:694；否则 = 首段 seq，
	// 因为我们无条件强制 start）。见 docs/TCP重组.md §7.3。
	// seen[d]：该方向是否已见过首段（用来区分「首段建立基准」与「后续段是否落在基准之前」）。
	// unreliable：粘性标记 —— 一旦本流出现过落在基准之前的段，永久为 true。
	baseline   [2]uint32
	seen       [2]bool
	unreliable bool
}

// Accept 接受所有 TCP 段。
//
// 对没有看到 SYN 的中途流也强制 start（*start = true），
// 这样单测/热路径即便只喂数据段也能建立流；真实握手流程同样兼容。
//
// ★ 行为基线不动（仍强制 start、仍返回 true），只在这里做 C′ 的簿记：
// 首次见该方向时记录基准；之后若某段落在基准之前且带载荷，就把它标成
// 「本流不可信」（粘性）并给 Reassembler 打一个仅本包有效的 preBaseline 标记。
func (s *stream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	if start != nil {
		*start = true
	}
	nd := s.g2n[dirIndex(dir)]
	if !s.seen[nd] {
		// 本方向首个观察段：记录 gopacket 将要设的 nextSeq（基准）。
		s.seen[nd] = true
		if tcp.SYN {
			s.baseline[nd] = tcp.Seq + 1
		} else {
			s.baseline[nd] = tcp.Seq
		}
		return true
	}
	// ★ 用 int32 差值判大小，天然处理 TCP 序号回绕（不要直接比 uint32）。
	// 只有带载荷的段会搁浅（空段不影响），与 §7.3 的根因链一致。
	if int32(tcp.Seq-s.baseline[nd]) < 0 && len(tcp.Payload) > 0 {
		s.unreliable = true
		if s.r != nil {
			s.r.preBaseline = true
		}
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
//
// ★ 返回值语义保持不变（true = 移出 gopacket 池，这正是我们要的）。改动的是 D：
// 先清理**我们自己的** byKey/byID 与缓冲，避免双向 FIN 之后仍持有已关闭的陈旧 stream
// （陈旧引用 + 缓冲滞留，见 docs/TCP重组.md §7.3）。
//
// ★ 安全性：本方法是在 gopacket 的装配过程中被调用的；我们只动自己的表与缓冲。
// Feed 在 AssembleWithContext **之后**才查 r.byKey[key] ⇒ 本次包查不到就自然 return；
// 同一四元组后续再来包时，gopacket 会重新建流（streamFactory.New）并把 byKey 换成新 stream。
func (s *stream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	if s.r != nil {
		s.r.dropStream(s)
	}
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
