package reassembly

// holes_test.go —— 洞 / 补齐 / 重传 的重组行为单测（任务 11-6）。
//
// 背景：11-2 之后 `alert tcp` 默认匹配 `stream` ⇒ 所有 TCP 规则命中都依赖重组质量；
// 而既有的 8 条重组测试没有覆盖「洞（丢包）/ 补齐 / 重传」。本文件按 gopacket 的
// 真实行为补这块回归网。
//
// ★ 实测结论（2026-10-14，与 docs/TCP重组.md §7 一致）：
//   gopacket 的 Assembler **不会**在洞面前 skip 交付，而是**先把洞之后的字节按序暂存、
//   等洞解决才交付** ⇒ 洞导致「延迟命中」而不是「跳过」。在没有 Flush/超时触发时，
//   `ReassembledSG` 收到的 `skip` 恒为 0，因此 `StatsOf().Gaps/GapBytes` 恒为 0
//   （这正是文档 §7 留的 P1：skip 路径需要 Flush 才能可靠触发，本任务不改生产代码，
//   故这里如实断言"延迟交付 + Gaps==0"，不假装观察到 skip）。
//
// 复用 reassembly_test.go 里的真实帧构造器 buildTCPPacket / tcpFlags / 固定四元组，
// 保证重组器能从帧里解出 TCP 序号（否则会静默忽略，测试"全绿但什么也没测"）。

import (
	"bytes"
	"testing"

	"flow-monitoring/internal/kernel/datamodel"
)

// holePkt 造一个属于流 1 的 TCP 数据段。
// ★ StatsOf 按 p.StreamID 索引，必须手工设为正数，否则查不到。
func holePkt(t *testing.T, seq uint32, payload []byte) *datamodel.Packet {
	t.Helper()
	p := buildTCPPacket(t, testSrc, testDst, testSrcPort, testDstPort, seq, tcpFlags{ack: true, psh: true}, payload)
	p.StreamID = 1
	return p
}

// holeSyn 造一个属于流 1 的 SYN（用来给乱序场景建立基准序号）。
func holeSyn(t *testing.T, seq uint32) *datamodel.Packet {
	t.Helper()
	p := buildTCPPacket(t, testSrc, testDst, testSrcPort, testDstPort, seq, tcpFlags{syn: true}, nil)
	p.StreamID = 1
	return p
}

// holeSnapshot 取「流 1、A→B」的统计与视图字节；StatsOf 查不到直接失败。
func holeSnapshot(t *testing.T, r *Reassembler, p *datamodel.Packet) (StreamStats, []byte) {
	t.Helper()
	st, ok := r.StatsOf(1, ToServer)
	if !ok {
		t.Fatalf("StatsOf(1, ToServer) 未命中：Feed 应已按 p.StreamID=1 建立映射")
	}
	return st, r.View(p).BytesToServer()
}

// TestGapHoldsBackLaterData：洞的实测行为。
//
// 同一条流依次喂 [0,10)、然后 [20,30)（中间 [10,20) 缺失）。
// ★ 按实测（见文件头结论）断言：gopacket 延迟交付 —— 补洞前 Bytes 只含 [0,10)，
//
//	[20,30) 在洞补上前看不到；Gaps/GapBytes 仍为 0（未走 skip 路径）。
func TestGapHoldsBackLaterData(t *testing.T) {
	r := New(DefaultOptions())
	defer r.Close()

	const front = "AAAAAAAAAA" // [0,10)  有数据
	const hole = "BBBBBBBBBB"  // [10,20) 缺失（本测试不喂）
	const later = "CCCCCCCCCC" // [20,30) 有数据

	p0 := holePkt(t, 0, []byte(front))
	p2 := holePkt(t, 20, []byte(later))

	r.Feed(p0)
	st, view := holeSnapshot(t, r, p0)
	t.Logf("step1 Feed [0,10):  Bytes=%d Gaps=%d GapBytes=%d ViewLen=%d View=%q",
		st.Bytes, st.Gaps, st.GapBytes, len(view), view)
	if st.Bytes != 10 || !bytes.Equal(view, []byte(front)) {
		t.Fatalf("step1: Bytes=%d View=%q, want Bytes=10 View=%q", st.Bytes, view, front)
	}

	r.Feed(p2) // [20,30) 到达，但 [10,20) 仍缺失
	st, view = holeSnapshot(t, r, p0)
	t.Logf("step2 Feed [20,30)（[10,20) 仍缺失）: Bytes=%d Gaps=%d GapBytes=%d ViewLen=%d View=%q",
		st.Bytes, st.Gaps, st.GapBytes, len(view), view)

	// 实测：延迟交付，不是 skip。
	if st.Bytes != 10 {
		t.Fatalf("洞未补齐前 Bytes=%d，want 10（延迟交付：只含 [0,10)）", st.Bytes)
	}
	if st.Gaps != 0 || st.GapBytes != 0 {
		t.Fatalf("洞未补齐前 Gaps=%d GapBytes=%d，want 0/0（无 Flush 时不走 skip 路径）", st.Gaps, st.GapBytes)
	}
	if !bytes.Equal(view, []byte(front)) {
		t.Fatalf("洞未补齐前 View=%q，want %q（[20,30) 应被暂存、不可见）", view, front)
	}
	if bytes.Contains(view, []byte(later)) {
		t.Fatalf("洞未补齐前不应看到 [20,30) 内容：View=%q", view)
	}
}

// TestGapFilledLaterRecovers：把缺失的 [10,20) 补上后，View 应恢复完整 [0,30)。
func TestGapFilledLaterRecovers(t *testing.T) {
	r := New(DefaultOptions())
	defer r.Close()

	full := []byte("0123456789ABCDEFGHIJabcdefghij") // 30 字节
	front, mid, tail := full[0:10], full[10:20], full[20:30]

	p0 := holePkt(t, 0, front)
	p1 := holePkt(t, 10, mid) // 缺失段：最后才喂
	p2 := holePkt(t, 20, tail)

	r.Feed(p0)
	st, view := holeSnapshot(t, r, p0)
	t.Logf("step1 Feed [0,10):            Bytes=%d Gaps=%d GapBytes=%d ViewLen=%d", st.Bytes, st.Gaps, st.GapBytes, len(view))

	r.Feed(p2) // 先到后段，洞 [10,20) 仍在
	st, view = holeSnapshot(t, r, p0)
	t.Logf("step2 Feed [20,30)（洞仍在）:  Bytes=%d Gaps=%d GapBytes=%d ViewLen=%d", st.Bytes, st.Gaps, st.GapBytes, len(view))
	if !bytes.Equal(view, front) {
		t.Fatalf("补洞前 View=%q，want %q", view, front)
	}

	r.Feed(p1) // 补齐洞
	st, view = holeSnapshot(t, r, p0)
	t.Logf("step3 Feed [10,20)（补洞）:    Bytes=%d Gaps=%d GapBytes=%d ViewLen=%d View=%q",
		st.Bytes, st.Gaps, st.GapBytes, len(view), view)

	if !bytes.Equal(view, full) {
		t.Fatalf("补洞后 View 不完整：got=%q\n want=%q", view, full)
	}
	if st.Bytes != int64(len(full)) {
		t.Fatalf("补洞后 Bytes=%d，want %d", st.Bytes, len(full))
	}
}

// TestRetransmitNotDuplicated：同一段（相同序号、相同载荷）连续喂两次，
// 最终内容不得重复、Bytes 不得翻倍。
func TestRetransmitNotDuplicated(t *testing.T) {
	r := New(DefaultOptions())
	defer r.Close()

	seg := []byte("0123456789")
	p := holePkt(t, 0, seg)

	r.Feed(p)
	st, view := holeSnapshot(t, r, p)
	t.Logf("step1 Feed [0,10):        Bytes=%d ViewLen=%d View=%q", st.Bytes, len(view), view)

	r.Feed(p) // 完全重传
	st, view = holeSnapshot(t, r, p)
	t.Logf("step2 重传同一段 [0,10):  Bytes=%d ViewLen=%d View=%q", st.Bytes, len(view), view)

	if !bytes.Equal(view, seg) {
		t.Fatalf("重传后 View=%q，want %q（不应出现重复）", view, seg)
	}
	if st.Bytes != int64(len(seg)) {
		t.Fatalf("重传后 Bytes=%d，want %d（重传不应使 Bytes 翻倍）", st.Bytes, len(seg))
	}
}

// TestOutOfOrderAcrossGap：把 3 段乱序到达，最终内容必须与按序喂入逐字节相同。
//
// ★ 用一个 SYN 建立基准序号（seq=1000 ⇒ 数据基准 1001）。原因是实测发现：
//
//	gopacket 的 Assembler 会把「落在 nextSeq 之后」的段暂存，而把「落在 nextSeq
//	之前」的段当作 overlap 丢弃。若没有基准、且乱序时先到达高序号段，低序号段会
//	被误判为已发送而丢弃（实测 [20,30)→[0,10)→[10,20) 只剩 [20,30)）。有了 SYN 基准，
//	任意乱序都能先暂存、待最小段到达后连续交付 ⇒ 结果与按序一致。
func TestOutOfOrderAcrossGap(t *testing.T) {
	seg1 := []byte("AAAAAAAAAA") // [1001,1011)
	seg2 := []byte("BBBBBBBBBB") // [1011,1021) 洞
	seg3 := []byte("CCCCCCCCCC") // [1021,1031)
	want := append(append(append([]byte(nil), seg1...), seg2...), seg3...)

	// 按序：SYN, seg1, seg2, seg3
	ordered := New(DefaultOptions())
	defer ordered.Close()
	synO := holeSyn(t, 1000)
	ordered.Feed(synO)
	st, view := holeSnapshot(t, ordered, synO)
	t.Logf("ordered step0 SYN:  Bytes=%d ViewLen=%d", st.Bytes, len(view))
	ordered.Feed(holePkt(t, 1001, seg1))
	ordered.Feed(holePkt(t, 1011, seg2))
	ordered.Feed(holePkt(t, 1021, seg3))
	st, orderedView := holeSnapshot(t, ordered, synO)
	t.Logf("ordered step1 依次 [1001,1011)/[1011,1021)/[1021,1031): Bytes=%d ViewLen=%d View=%q",
		st.Bytes, len(orderedView), orderedView)

	// 乱序：SYN, seg3, seg1, seg2
	reordered := New(DefaultOptions())
	defer reordered.Close()
	synR := holeSyn(t, 1000)
	reordered.Feed(synR)
	reordered.Feed(holePkt(t, 1021, seg3)) // 后段先到（暂存）
	st, view = holeSnapshot(t, reordered, synR)
	t.Logf("reorder step1 Feed [1021,1031)（洞中）: Bytes=%d ViewLen=%d", st.Bytes, len(view))
	reordered.Feed(holePkt(t, 1001, seg1)) // 最小段到达（交付 + 暂存仍缺中间）
	st, view = holeSnapshot(t, reordered, synR)
	t.Logf("reorder step2 Feed [1001,1011):        Bytes=%d ViewLen=%d View=%q", st.Bytes, len(view), view)
	reordered.Feed(holePkt(t, 1011, seg2)) // 补齐洞
	st, reorderedView := holeSnapshot(t, reordered, synR)
	t.Logf("reorder step3 Feed [1011,1021)（补洞）: Bytes=%d ViewLen=%d View=%q",
		st.Bytes, len(reorderedView), reorderedView)

	if !bytes.Equal(orderedView, want) {
		t.Fatalf("按序结果=%q，want %q", orderedView, want)
	}
	if !bytes.Equal(reorderedView, want) {
		t.Fatalf("乱序结果=%q，want %q", reorderedView, want)
	}
	if !bytes.Equal(reorderedView, orderedView) {
		t.Fatalf("乱序与按序结果不同：\n reorder=%q\n ordered=%q", reorderedView, orderedView)
	}
}
