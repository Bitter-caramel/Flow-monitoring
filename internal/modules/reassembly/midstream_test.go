package reassembly

// midstream_test.go —— 「中途流（无 SYN）+ 乱序」的诊断与修复守卫（任务 11-6c / 11-6c-fix）。
//
// ★ 11-6c 是**诊断**（只加测试）；11-6c-fix 之后本文件同时守卫两件事：
//   ① 诊断结论本身（把 PM 探针实测到的行为钉成断言）；
//   ② 修复后的新行为：D（ReassemblyComplete 顺手清理我们自己的 byKey/byID + 缓冲）与
//      C′ 的簿记（只有「真的出现过落在基准之前的段」的流才被标 `Midstream()`）。
//   其中 TestMidstreamStreamNotEvictedByReorder 的第 5 步是**刻意翻转**的断言
//   （原断言记录的是"我们仍持旧 stream"这个缺陷）。
//
// 背景（PM 探针实测，同一条流、同一五元组）：
//
//	无 SYN，按序 [A,B,C]                     => View = AAAABBBBCCCC（完整）
//	无 SYN，乱序 [C,A,B]                     => View = CCCC（★ A、B 被静默丢弃）
//	无 SYN，乱序 [A,C,B]                     => View = AAAABBBBCCCC（完整）
//	无 SYN，首段为高序号空载荷 [1000,C,A,B]  => View = 空（★★ 该方向后续全部不可见）
//
// 根因（详见任务报告「源码溯源」，gopacket v1.7.4 reassembly/tcpassembly.go）：
// 我们的 stream.Accept 无条件把 *start 置 true（stream.go），gopacket 于是把
// 「首个观察到的段」的 seq 当作 nextSeq（基准）；此后任何 seq < nextSeq 的段都落进
// 非 queue 分支，被 overlapExisting 当作重叠整段丢弃 ⇒ 静默少匹配。
//
// 复用 reassembly_test.go 的真实帧构造器 buildTCPPacket / tcpFlags / 固定四元组，
// 保证重组器能从帧里解出 TCP 序号（否则会静默忽略，测试「全绿但什么都没测」）。

import (
	"bytes"
	"testing"

	"flow-monitoring/internal/kernel/datamodel"
)

// 三个数据段：A=[1001,1005) B=[1005,1009) C=[1009,1013)，各 4 字节。
const (
	midSegA = "AAAA"
	midSegB = "BBBB"
	midSegC = "CCCC"

	midSeqA = uint32(1001)
	midSeqB = uint32(1005)
	midSeqC = uint32(1009)

	// 首段是「高序号空载荷段」时用的 seq（比 A 还小 1 字节）。
	midSeqHighEmpty = uint32(1000)
)

// midWantFull 是按序号应重组成的内容。
const midWantFull = midSegA + midSegB + midSegC // "AAAABBBBCCCC"

// midPkt 造一个属于流 1 的 A→B TCP 数据段（ACK+PSH）。
// ★ View/StatsOf 按 p.StreamID 定位，必须给所有包设同一个正数。
func midPkt(t *testing.T, seq uint32, payload []byte) *datamodel.Packet {
	t.Helper()
	p := buildTCPPacket(t, testSrc, testDst, testSrcPort, testDstPort, seq, tcpFlags{ack: true, psh: true}, payload)
	p.StreamID = 1
	return p
}

// midSyn 造一个属于流 1 的**真 SYN**（seq 会被 gopacket 变成 seq+1 作基准）。
// ★ 真 SYN 必须用 tcpFlags{syn: true}：不能拿「空载荷数据段」冒充。
func midSyn(t *testing.T, seq uint32) *datamodel.Packet {
	t.Helper()
	p := buildTCPPacket(t, testSrc, testDst, testSrcPort, testDstPort, seq, tcpFlags{syn: true}, nil)
	p.StreamID = 1
	return p
}

// midFinRev 造一个属于流 1 的 B→A 方向 FIN（无载荷），用于观察「两方向都关闭」后的行为。
func midFinRev(t *testing.T, seq uint32) *datamodel.Packet {
	t.Helper()
	p := buildTCPPacket(t, testDst, testSrc, testDstPort, testSrcPort, seq, tcpFlags{fin: true}, nil)
	p.StreamID = 1
	return p
}

// feedLog 喂一个包，并打印本流当前的 FlowCount/Bytes/视图（A→B），返回视图字节。
// 便于观察每个中间步骤「看到了什么」以及「流是否被移出 / 重建」。
func feedLog(t *testing.T, r *Reassembler, label string, p *datamodel.Packet) []byte {
	t.Helper()
	r.Feed(p)
	got := r.View(p).BytesToServer()
	t.Logf("%s: FlowCount=%d Bytes=%d ViewLen=%d View=%q", label, r.FlowCount(), r.Bytes(), len(got), got)
	return got
}

// TestMidstreamInOrderComplete：无 SYN，按序 [A,B,C] ⇒ 完整 12 字节（基线/对照组）。
func TestMidstreamInOrderComplete(t *testing.T) {
	r := New(DefaultOptions())
	defer r.Close()

	a := midPkt(t, midSeqA, []byte(midSegA))
	b := midPkt(t, midSeqB, []byte(midSegB))
	c := midPkt(t, midSeqC, []byte(midSegC))

	feedLog(t, r, "1) Feed A=[1001,1005)", a)
	feedLog(t, r, "2) Feed B=[1005,1009)", b)
	got := feedLog(t, r, "3) Feed C=[1009,1013)", c)

	if !bytes.Equal(got, []byte(midWantFull)) {
		t.Fatalf("按序 View=%q, want %q", got, midWantFull)
	}
}

// TestMidstreamReorderDropsEarlySegments：无 SYN，乱序 [C,A,B]。
//
// ★★ 这是**当前实现的缺陷**（Accept 无条件强制 start ⇒ 基准被钉成首个观察段 C 的 seq）：
//
//	gopacket 把落在基准之前的 A、B 当 overlap 整段丢弃，View 只剩 "CCCC"。
//
// ★ 修好之后本测试会**刻意翻转**：期望应改为完整的 midWantFull（12 字节）。
// 现在如实断言当前行为，作为「修前基线 / 红转绿守卫」。
func TestMidstreamReorderDropsEarlySegments(t *testing.T) {
	r := New(DefaultOptions())
	defer r.Close()

	c := midPkt(t, midSeqC, []byte(midSegC))
	a := midPkt(t, midSeqA, []byte(midSegA))
	b := midPkt(t, midSeqB, []byte(midSegB))

	first := feedLog(t, r, "1) Feed C=[1009,1013)（高序号先到，成为基准）", c)
	if !bytes.Equal(first, []byte(midSegC)) {
		t.Fatalf("首个段 View=%q, want %q", first, midSegC)
	}
	feedLog(t, r, "2) Feed A=[1001,1005)（落在基准之前）", a)
	got := feedLog(t, r, "3) Feed B=[1005,1009)（落在基准之前）", b)

	// ★ 缺陷基线：A、B 被丢弃，只剩 C。修好后这一行必须改成 midWantFull。
	buggyWant := midSegC
	if !bytes.Equal(got, []byte(buggyWant)) {
		t.Fatalf("乱序 [C,A,B] View=%q, 当前缺陷行为应为 %q（修复后应翻转为 %q）",
			got, buggyWant, midWantFull)
	}
	if len(got) != 4 {
		t.Fatalf("乱序 [C,A,B] ViewLen=%d, 当前缺陷行为应为 4", len(got))
	}
}

// TestMidstreamReorderKeepsLowestFirst：无 SYN，乱序 [A,C,B] ⇒ 完整 12 字节（对照组）。
//
// 首段是最小序号 A ⇒ 基准=A 的 seq ⇒ C 进乱序暂存、B 到达后连续交付并顺势带出 C。
func TestMidstreamReorderKeepsLowestFirst(t *testing.T) {
	r := New(DefaultOptions())
	defer r.Close()

	a := midPkt(t, midSeqA, []byte(midSegA))
	c := midPkt(t, midSeqC, []byte(midSegC))
	b := midPkt(t, midSeqB, []byte(midSegB))

	feedLog(t, r, "1) Feed A=[1001,1005)（最小段先到，成为基准）", a)
	feedLog(t, r, "2) Feed C=[1009,1013)（暂存）", c)
	got := feedLog(t, r, "3) Feed B=[1005,1009)（补齐，带出 C）", b)

	if !bytes.Equal(got, []byte(midWantFull)) {
		t.Fatalf("乱序 [A,C,B] View=%q, want %q", got, midWantFull)
	}
	if len(got) != 12 {
		t.Fatalf("乱序 [A,C,B] ViewLen=%d, want 12", len(got))
	}
}

// TestMidstreamHighSeqFirstBlocksAll：无 SYN，首段为高序号空载荷段（seq=1000），随后 [C,A,B]。
//
// ★★ 当前缺陷（更严重）：空载荷首段把基准钉成 1000，而 seq==1000 的段没数据、也没人补这个
// 空洞 ⇒ 之后的 C/A/B（seq 都 > 1000）全部进乱序暂存、永不交付 ⇒ 整个方向后续不可见，
// View 为空（PM 实测为 “）。
func TestMidstreamHighSeqFirstBlocksAll(t *testing.T) {
	r := New(DefaultOptions())
	defer r.Close()

	empty := midPkt(t, midSeqHighEmpty, nil) // seq=1000，空载荷
	c := midPkt(t, midSeqC, []byte(midSegC))
	a := midPkt(t, midSeqA, []byte(midSegA))
	b := midPkt(t, midSeqB, []byte(midSegB))

	feedLog(t, r, "1) Feed 高序号空载荷 [1000,1000)（把基准钉在 1000）", empty)
	feedLog(t, r, "2) Feed C=[1009,1013)（> 基准，暂存）", c)
	feedLog(t, r, "3) Feed A=[1001,1005)（> 基准，暂存）", a)
	got := feedLog(t, r, "4) Feed B=[1005,1009)（> 基准，暂存）", b)

	// ★ 缺陷基线：永远是空。修好后应能交付（至少不再是空）。
	if len(got) != 0 {
		t.Fatalf("首段高序号空载荷时 ViewLen=%d（%q）, 当前缺陷行为应为 0（该方向全部不可见）", len(got), got)
	}
}

// TestMidstreamWithSynReorder：**真的有 SYN**（tcpFlags{syn:true}, seq=1000）之后再 [C,A,B]。
//
// ★ 与第 2/4 条对比，用来区分「基准是否被设成首个观察段」与「真 SYN 是否改变基准」：
// 真 SYN 先到 ⇒ gopacket 把 nextSeq 设为 SYN.seq+1=1001（而不是首个观察数据段），
// 于是 C 进乱序暂存、A 到达后连续交付并带出 B、C ⇒ 完整 12 字节。
func TestMidstreamWithSynReorder(t *testing.T) {
	r := New(DefaultOptions())
	defer r.Close()

	syn := midSyn(t, 1000) // 真 SYN；仅用于建立基准 1001
	c := midPkt(t, midSeqC, []byte(midSegC))
	a := midPkt(t, midSeqA, []byte(midSegA))
	b := midPkt(t, midSeqB, []byte(midSegB))

	feedLog(t, r, "1) Feed 真 SYN(seq=1000)（基准置为 1001）", syn)
	feedLog(t, r, "2) Feed C=[1009,1013)（> 基准，暂存）", c)
	feedLog(t, r, "3) Feed A=[1001,1005)（== 基准，交付并带出 B、C）", a)
	got := feedLog(t, r, "4) Feed B=[1005,1009)", b)

	if !bytes.Equal(got, []byte(midWantFull)) {
		t.Fatalf("真 SYN + 乱序 [C,A,B] View=%q, want %q", got, midWantFull)
	}
	if len(got) != 12 {
		t.Fatalf("真 SYN + 乱序 [C,A,B] ViewLen=%d, want 12", len(got))
	}
}

// TestMidstreamStreamNotEvictedByReorder 是**只读的辨别实验**，回答「更小序号段被丢弃」是否
// 由下述两点造成，而不是别的机制：
//
//	① 流被过早移出 gopacket 池（ReassemblyComplete 恒返回 true）；
//	② 我们 byID/byKey 里持有的 stream 变陈旧（视图看不到数据）。
//
// 结论（实测，见 t.Logf 输出）：
//   - 纯乱序丢弃期间（无 FIN/RST、无超时关闭）：byKey/byID 指针始终指向**同一个** stream 对象，
//     FlowCount 恒为 1、Bytes 不重置 ⇒ 流**没有**被移出/重建；丢弃来自 gopacket 的 overlap 逻辑。
//   - 只有「两个 half 都 closed」时 gopacket 才调用 ReassemblyComplete（tcpassembly.go:1213-1216）；
//     本仓库实现恒返回 true ⇒ 连接被移出池。此后同一五元组再来一个段会被当作**新连接**、
//     调用 factory.New 生成**新 stream** 覆盖 byKey/byID（旧缓冲变陈旧、视图看不到）。
//     这一步用两方向 FIN 复现，证明「恒 true」确有代价，但**不是**中途乱序丢段的成因。
func TestMidstreamStreamNotEvictedByReorder(t *testing.T) {
	r := New(DefaultOptions())
	defer r.Close()

	key, _ := keyFrom(testSrc.To4(), testDst.To4(), testSrcPort, testDstPort)

	// ── 阶段一：模拟中途乱序 [C,A,B]，观察流对象是否稳定 ──
	c := midPkt(t, midSeqC, []byte(midSegC))
	a := midPkt(t, midSeqA, []byte(midSegA))
	b := midPkt(t, midSeqB, []byte(midSegB))

	r.Feed(c)
	s0 := r.byKey[key]
	if s0 == nil {
		t.Fatalf("喂入首个段后 byKey 应已有流")
	}
	t.Logf("阶段一 step1 Feed C: byKey=%p byID[1]=%p FlowCount=%d Bytes=%d", s0, r.byID[1], r.FlowCount(), r.Bytes())

	r.Feed(a)
	t.Logf("阶段一 step2 Feed A: byKey=%p byID[1]=%p FlowCount=%d Bytes=%d（指针是否不变=%v）",
		r.byKey[key], r.byID[1], r.FlowCount(), r.Bytes(), r.byKey[key] == s0)

	r.Feed(b)
	t.Logf("阶段一 step3 Feed B: byKey=%p byID[1]=%p FlowCount=%d Bytes=%d View=%q（指针是否不变=%v）",
		r.byKey[key], r.byID[1], r.FlowCount(), r.Bytes(), r.View(b).BytesToServer(), r.byKey[key] == s0)

	// ★ 纯乱序丢弃期间：流对象必须稳定，说明丢弃不是「移出/重建」造成的。
	if r.byKey[key] != s0 {
		t.Fatalf("乱序丢弃期间 byKey 指向的 stream 变了：got=%p want=%p（不应被移出/重建）", r.byKey[key], s0)
	}
	if r.byID[1] != s0 {
		t.Fatalf("乱序丢弃期间 byID[1] 指向的 stream 变了：got=%p want=%p", r.byID[1], s0)
	}
	if r.FlowCount() != 1 {
		t.Fatalf("乱序丢弃期间 FlowCount=%d, want 1", r.FlowCount())
	}
	if r.Bytes() != 4 {
		t.Fatalf("乱序丢弃期间 Bytes=%d, want 4（只有 C 被交付，且未被重建清零）", r.Bytes())
	}

	// ── 阶段二：对照实验，验证 ReassemblyComplete 的调用时机 ──
	// 单方向 FIN 只关一个 half ⇒ gopacket 不调用 ReassemblyComplete ⇒ 池里连接仍在。
	finUp := buildTCPPacket(t, testSrc, testDst, testSrcPort, testDstPort, midSeqC+uint32(len(midSegC)), tcpFlags{fin: true}, nil)
	finUp.StreamID = 1
	r.Feed(finUp)
	t.Logf("阶段二 step4 Feed FIN A->B(seq=%d): byKey=%p FlowCount=%d Bytes=%d（单方向 FIN，指针仍不变=%v）",
		midSeqC+uint32(len(midSegC)), r.byKey[key], r.FlowCount(), r.Bytes(), r.byKey[key] == s0)
	if r.byKey[key] != s0 {
		t.Fatalf("单方向 FIN 不应导致重建：byKey=%p want=%p", r.byKey[key], s0)
	}

	// 第二方向 FIN ⇒ 两个 half 都 closed ⇒ ReassemblyComplete(true) ⇒ connPool.remove。
	//
	// ★ 11-6c-fix（D）之后**刻意翻转**的断言：以前我们只让 gopacket 把连接移出池，
	// **自己的 byKey/byID 仍持有已关闭的旧 stream**（陈旧引用 + 缓冲滞留，docs §7.3）。
	// D 让 ReassemblyComplete 顺手 dropStream ⇒ 现在两个方向 FIN 之后我们自己也要摘干净。
	finDown := midFinRev(t, 0)
	r.Feed(finDown)
	t.Logf("阶段二 step5 Feed FIN B->A: byKey=%p byID[1]=%p FlowCount=%d Bytes=%d（D 之后应已摘干净）",
		r.byKey[key], r.byID[1], r.FlowCount(), r.Bytes())
	if r.byKey[key] != nil {
		t.Fatalf("两方向 FIN 后 byKey 应已摘掉旧 stream（D 的清理），实际=%p", r.byKey[key])
	}
	if r.byID[1] != nil {
		t.Fatalf("两方向 FIN 后 byID[1] 应已摘掉旧 stream（D 的清理），实际=%p", r.byID[1])
	}
	if r.FlowCount() != 0 {
		t.Fatalf("两方向 FIN 后 FlowCount=%d, want 0", r.FlowCount())
	}
	if r.Bytes() != 0 {
		t.Fatalf("两方向 FIN 后 Bytes=%d, want 0（旧缓冲应已释放）", r.Bytes())
	}

	// 再来一个数据段：gopacket 池里连接已被移除 ⇒ 视作新连接 ⇒ factory.New 生成新 stream。
	fresh := midPkt(t, 5000, []byte("NEW"))
	r.Feed(fresh)
	sNew := r.byKey[key]
	view := r.View(fresh).BytesToServer()
	t.Logf("阶段二 step6 Feed 新数据段: byKey=%p（是否重建=%v） byID[1]=%p View=%q",
		sNew, sNew != s0, r.byID[1], view)

	if sNew == s0 {
		t.Fatalf("两方向 FIN 移出池后，新段应触发 factory.New 重建 stream（byKey 应变指针）")
	}
	if r.byID[1] != sNew {
		t.Fatalf("重建后 byID[1]=%p 应指向新 stream %p", r.byID[1], sNew)
	}
	if !bytes.Equal(view, []byte("NEW")) {
		t.Fatalf("重建后 View=%q, want %q（旧缓冲 %q 已不可见）", view, "NEW", midSegC)
	}
}

// TestMidstreamPreBaselineMarksUnreliable 覆盖 11-6c-fix 的 C′ 簿记（窄口径防漏的判据）：
// 只有「真的出现过落在基准之前的段」的流才被标成不可信（`View(...).Midstream() == true`），
// 其它中途流（乱序但不越基准，如 [A,C,B]）以及「根本没有流」的空视图都必须保持 false。
//
// ★ 为什么必须钉住这三面：C′ 的作用是**只让不可信的包/流回落 payload**；
// 一旦判宽了（比如把「没有流」也算不可信、或按"无 SYN"一刀切），就会牺牲中途流的
// 跨包签名匹配 —— 那是被明确否掉的方案（用户 2026-10-14 拍板用 C′）。
func TestMidstreamPreBaselineMarksUnreliable(t *testing.T) {
	t.Run("乱序越基准_标记不可信且粘性", func(t *testing.T) {
		r := New(DefaultOptions())
		defer r.Close()

		c := midPkt(t, midSeqC, []byte(midSegC)) // 首个段：基准被钉在 1009
		r.Feed(c)
		if got := r.View(c).Midstream(); got {
			t.Fatalf("喂首个段后 Midstream()=true，want false（还没出现越基准的段）")
		}

		a := midPkt(t, midSeqA, []byte(midSegA)) // 1001 < 基准 1009 ⇒ 越基准
		r.Feed(a)
		if got := r.View(a).Midstream(); !got {
			t.Fatalf("喂越基准的段后 Midstream()=false，want true（本包应回落 payload）")
		}

		b := midPkt(t, midSeqB, []byte(midSegB)) // 1005 < 基准 ⇒ 仍越基准；且标记应粘住
		r.Feed(b)
		if got := r.View(b).Midstream(); !got {
			t.Fatalf("后续包 Midstream()=false，want true（unreliable 是粘性标记）")
		}
		t.Logf("越基准流：View=%q（只交付了基准之后的 C，A/B 搁浅）", r.View(b).BytesToServer())
	})

	t.Run("乱序不越基准_不标记", func(t *testing.T) {
		r := New(DefaultOptions())
		defer r.Close()

		a := midPkt(t, midSeqA, []byte(midSegA)) // 最小段先到 ⇒ 基准 1001
		r.Feed(a)
		c := midPkt(t, midSeqC, []byte(midSegC)) // 1009 > 基准 ⇒ 只是暂存，不越基准
		r.Feed(c)
		b := midPkt(t, midSeqB, []byte(midSegB)) // 1005 > 基准
		r.Feed(b)

		if got := r.View(b).Midstream(); got {
			t.Fatalf("乱序但未越基准的流 Midstream()=true，want false（不该回落 payload）")
		}
		if got := r.View(b).BytesToServer(); !bytes.Equal(got, []byte(midWantFull)) {
			t.Fatalf("View=%q, want %q", got, midWantFull)
		}
	})

	t.Run("空视图不算中途流", func(t *testing.T) {
		r := New(DefaultOptions())
		defer r.Close()

		// 完全没喂过的流：View 走不到 byID/byKey ⇒ 空视图。
		p := midPkt(t, midSeqA, []byte(midSegA))
		if got := r.View(p).Midstream(); got {
			t.Fatalf("没有流的空视图 Midstream()=true，want false（★ 否则所有无流包都会回落 payload）")
		}
	})
}
