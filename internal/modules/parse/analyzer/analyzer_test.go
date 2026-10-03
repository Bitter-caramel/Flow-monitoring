package analyzer

import (
	"testing"
	"time"

	"flow-monitoring/internal/kernel/datamodel"
)

// 常用测试地址（IPv4 整数）。
const (
	ipA = uint32(0x0A000001) // 10.0.0.1（低地址）
	ipB = uint32(0x0A000002) // 10.0.0.2（高地址）
)

// mkPkt 构造一个 IPv4 TCP/UDP 测试包。
func mkPkt(src, dst uint32, sp, dp uint16, proto uint8, capLen, payloadLen int, ts time.Time) *datamodel.Packet {
	p := datamodel.NewPacket()
	p.IPVersion = 4
	p.SrcIPNum = src
	p.DstIPNum = dst
	p.SrcPort = sp
	p.DstPort = dp
	p.IPProto = proto
	p.CapLen = capLen
	p.PayloadLen = payloadLen
	p.Time = ts
	return p
}

// TestAnalyzer_MergeBothDirections 覆盖同一五元组双向归并、方向计数、统计与回写。
func TestAnalyzer_MergeBothDirections(t *testing.T) {
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)

	a := New()

	// A→B（源地址较低，dir=0）
	p1 := mkPkt(ipA, ipB, 1234, 80, 6, 60, 10, base)
	// B→A（源地址较高，dir=1）
	p2 := mkPkt(ipB, ipA, 80, 1234, 6, 100, 50, base.Add(1*time.Second))
	// A→B 再来一个
	p3 := mkPkt(ipA, ipB, 1234, 80, 6, 40, 0, base.Add(2*time.Second))

	a.Feed(p1)
	a.Feed(p2)
	a.Feed(p3)

	// 只有一条流
	if got := a.Len(); got != 1 {
		t.Fatalf("Len() = %d, want 1", got)
	}
	if got := len(a.Flows()); got != 1 {
		t.Fatalf("len(Flows()) = %d, want 1", got)
	}

	// 按规范化五元组查询：A=低地址(ipA:1234)，B=高地址(ipB:80)
	f := a.Flow(ipA, 1234, ipB, 80, 6)
	if f == nil {
		t.Fatalf("Flow(ipA,1234,ipB,80,6) = nil, want non-nil")
	}
	if f.ID != 1 {
		t.Errorf("Flow.ID = %d, want 1", f.ID)
	}
	if f.Kind != "tcp" {
		t.Errorf("Flow.Kind = %q, want tcp", f.Kind)
	}
	if f.A != ipA || f.APort != 1234 || f.B != ipB || f.BPort != 80 || f.Protocol != 6 {
		t.Errorf("Flow five-tuple = (%d,%d,%d,%d,%d), want (%d,1234,%d,80,6)",
			f.A, f.APort, f.B, f.BPort, f.Protocol, ipA, ipB)
	}
	if f.Swap {
		t.Errorf("Flow.Swap = true, want false（先出现的是低地址方向）")
	}

	// 包数、字节数
	if f.PacketCnt != 3 {
		t.Errorf("PacketCnt = %d, want 3", f.PacketCnt)
	}
	if f.ByteCnt != 60+100+40 {
		t.Errorf("ByteCnt = %d, want %d", f.ByteCnt, 60+100+40)
	}

	// 方向计数：[0]=A→B, [1]=B→A
	if f.Dirs[0].Packets != 2 {
		t.Errorf("Dirs[0].Packets = %d, want 2", f.Dirs[0].Packets)
	}
	if f.Dirs[0].Bytes != 60+40 {
		t.Errorf("Dirs[0].Bytes = %d, want %d", f.Dirs[0].Bytes, 60+40)
	}
	if f.Dirs[0].DataBytes != 10 {
		t.Errorf("Dirs[0].DataBytes = %d, want 10", f.Dirs[0].DataBytes)
	}
	if f.Dirs[1].Packets != 1 {
		t.Errorf("Dirs[1].Packets = %d, want 1", f.Dirs[1].Packets)
	}
	if f.Dirs[1].Bytes != 100 {
		t.Errorf("Dirs[1].Bytes = %d, want 100", f.Dirs[1].Bytes)
	}
	if f.Dirs[1].DataBytes != 50 {
		t.Errorf("Dirs[1].DataBytes = %d, want 50", f.Dirs[1].DataBytes)
	}

	// 首末时间
	if !f.FirstSeen.Equal(base) {
		t.Errorf("FirstSeen = %v, want %v", f.FirstSeen, base)
	}
	if !f.LastSeen.Equal(base.Add(2 * time.Second)) {
		t.Errorf("LastSeen = %v, want %v", f.LastSeen, base.Add(2*time.Second))
	}

	// 回写 p.StreamID / p.StreamDir
	if p1.StreamID != 1 || p1.StreamDir != 0 {
		t.Errorf("p1 stream = (%d,%d), want (1,0)", p1.StreamID, p1.StreamDir)
	}
	if p2.StreamID != 1 || p2.StreamDir != 1 {
		t.Errorf("p2 stream = (%d,%d), want (1,1)", p2.StreamID, p2.StreamDir)
	}
	if p3.StreamID != 1 || p3.StreamDir != 0 {
		t.Errorf("p3 stream = (%d,%d), want (1,0)", p3.StreamID, p3.StreamDir)
	}
}

// TestAnalyzer_SkipUnsupported 覆盖非 TCP/UDP、IPv6 与 nil 包被跳过。
func TestAnalyzer_SkipUnsupported(t *testing.T) {
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	a := New()

	// 先放入一个合法 TCP 包，确认后续被跳过的包不会新建流。
	a.Feed(mkPkt(ipA, ipB, 1234, 80, 6, 60, 10, base))
	if got := a.Len(); got != 1 {
		t.Fatalf("Len() after valid packet = %d, want 1", got)
	}

	// ICMP（IPProto=1）
	icmp := mkPkt(ipA, ipB, 0, 0, 1, 80, 0, base)
	// IPv6（IPVersion=6），协议号为 TCP 也应跳过
	v6 := mkPkt(ipA, ipB, 1234, 80, 6, 60, 10, base)
	v6.IPVersion = 6
	// 其它 IP 协议号（GRE=47）
	gre := mkPkt(ipA, ipB, 0, 0, 47, 60, 0, base)

	a.Feed(icmp)
	a.Feed(v6)
	a.Feed(gre)
	a.Feed(nil) // nil 包不应 panic

	if got := a.Len(); got != 1 {
		t.Errorf("Len() after skipped packets = %d, want 1", got)
	}
	// 被跳过包不应被回写流归属
	if icmp.StreamID != -1 || icmp.StreamDir != 0 {
		t.Errorf("icmp stream = (%d,%d), want (-1,0)", icmp.StreamID, icmp.StreamDir)
	}
	if v6.StreamID != -1 {
		t.Errorf("ipv6 StreamID = %d, want -1", v6.StreamID)
	}
	if gre.StreamID != -1 {
		t.Errorf("gre StreamID = %d, want -1", gre.StreamID)
	}
}

// TestAnalyzer_FlowLookupAndLen 覆盖 Flow() 命中/未命中与 Len() 计数。
func TestAnalyzer_FlowLookupAndLen(t *testing.T) {
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	a := New()

	if got := a.Len(); got != 0 {
		t.Errorf("empty Len() = %d, want 0", got)
	}

	a.Feed(mkPkt(ipA, ipB, 1234, 80, 6, 60, 10, base))  // TCP 流 1
	a.Feed(mkPkt(ipB, ipA, 53, 5353, 17, 70, 20, base)) // UDP 流 2

	if got := a.Len(); got != 2 {
		t.Fatalf("Len() = %d, want 2", got)
	}

	// 命中（规范化五元组）
	if f := a.Flow(ipA, 1234, ipB, 80, 6); f == nil {
		t.Error("Flow(ipA,1234,ipB,80,6) = nil, want non-nil")
	}
	if f := a.Flow(ipA, 5353, ipB, 53, 17); f == nil {
		t.Error("Flow(ipA,5353,ipB,53,17) = nil, want non-nil")
	}

	// 未命中：反向五元组未规范化
	if f := a.Flow(ipB, 80, ipA, 1234, 6); f != nil {
		t.Errorf("reverse lookup = %+v, want nil", f)
	}
	// 未命中：端口/协议不同
	if f := a.Flow(ipA, 1234, ipB, 443, 6); f != nil {
		t.Errorf("wrong port lookup = %+v, want nil", f)
	}
	if f := a.Flow(ipA, 1234, ipB, 80, 17); f != nil {
		t.Errorf("wrong proto lookup = %+v, want nil", f)
	}
	if f := a.Flow(ipA, 1234, ipB, 80, 6); f == nil {
		t.Error("lookup after misses = nil, want non-nil")
	}

	// nil 接收者不应 panic
	var nilA *Analyzer
	if f := nilA.Flow(ipA, 1234, ipB, 80, 6); f != nil {
		t.Errorf("nil analyzer Flow = %+v, want nil", f)
	}
	if got := nilA.Len(); got != 0 {
		t.Errorf("nil analyzer Len = %d, want 0", got)
	}
}

// TestAnalyzer_SwapWhenHighAddrFirst 覆盖高地址方向先出现时 Swap 标记与规范化。
func TestAnalyzer_SwapWhenHighAddrFirst(t *testing.T) {
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	a := New()

	// 先用 B→A（源地址较高）喂入，流应以 A=低地址 规范化并置 Swap=true。
	p := mkPkt(ipB, ipA, 80, 1234, 6, 100, 50, base)
	a.Feed(p)

	f := a.Flow(ipA, 1234, ipB, 80, 6)
	if f == nil {
		t.Fatalf("Flow(ipA,1234,ipB,80,6) = nil, want non-nil")
	}
	if f.A != ipA || f.APort != 1234 || f.B != ipB || f.BPort != 80 {
		t.Errorf("five-tuple = (%d,%d,%d,%d), want (%d,1234,%d,80)", f.A, f.APort, f.B, f.BPort, ipA, ipB)
	}
	if !f.Swap {
		t.Error("Swap = false, want true（先出现的是高地址方向）")
	}
	if p.StreamDir != 1 {
		t.Errorf("p.StreamDir = %d, want 1", p.StreamDir)
	}
	if f.Dirs[0].Packets != 0 || f.Dirs[1].Packets != 1 {
		t.Errorf("Dirs packets = (%d,%d), want (0,1)", f.Dirs[0].Packets, f.Dirs[1].Packets)
	}
}

// TestAnalyzer_SameIPPortNormalization 覆盖 IP 相等时退化到端口比较的规范化分支。
func TestAnalyzer_SameIPPortNormalization(t *testing.T) {
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	a := New()

	// 同一 IP，源端口较大 -> 目的端口为 A 方向，dir=1。
	a.Feed(mkPkt(ipA, ipA, 9000, 80, 6, 10, 1, base))

	if got := a.Len(); got != 1 {
		t.Fatalf("Len() = %d, want 1", got)
	}
	f := a.Flow(ipA, 80, ipA, 9000, 6)
	if f == nil {
		t.Fatalf("Flow(ipA,80,ipA,9000,6) = nil, want non-nil")
	}
	if f.APort != 80 || f.BPort != 9000 {
		t.Errorf("ports = (%d,%d), want (80,9000)", f.APort, f.BPort)
	}
	if !f.Swap || f.Dirs[1].Packets != 1 {
		t.Errorf("Swap=%v Dirs[1].Packets=%d, want true/1", f.Swap, f.Dirs[1].Packets)
	}

	// 反方向同 IP，源端口较小 -> dir=0，归并到同一条流。
	a.Feed(mkPkt(ipA, ipA, 80, 9000, 6, 20, 2, base))
	if got := a.Len(); got != 1 {
		t.Errorf("Len() after reverse = %d, want 1", got)
	}
	if f.PacketCnt != 2 || f.Dirs[0].Packets != 1 || f.Dirs[1].Packets != 1 {
		t.Errorf("PacketCnt=%d Dirs=(%d,%d), want 2/(1,1)", f.PacketCnt, f.Dirs[0].Packets, f.Dirs[1].Packets)
	}
}

// TestAnalyzer_UDPKind 覆盖 UDP 流的 Kind 与 UDP 端口方向规范化。
func TestAnalyzer_UDPKind(t *testing.T) {
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	a := New()

	a.Feed(mkPkt(ipA, ipB, 5353, 53, 17, 70, 20, base))

	f := a.Flow(ipA, 5353, ipB, 53, 17)
	if f == nil {
		t.Fatalf("UDP flow lookup = nil, want non-nil")
	}
	if f.Kind != "udp" {
		t.Errorf("Kind = %q, want udp", f.Kind)
	}
	if f.Protocol != 17 {
		t.Errorf("Protocol = %d, want 17", f.Protocol)
	}
}

// TestAnalyzer_FlowsOrderAndCopy 覆盖 Flows() 的创建顺序与返回副本语义。
func TestAnalyzer_FlowsOrderAndCopy(t *testing.T) {
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	a := New()

	a.Feed(mkPkt(ipA, ipB, 1234, 80, 6, 60, 10, base))  // ID 1
	a.Feed(mkPkt(ipA, ipB, 1235, 80, 6, 60, 10, base))  // ID 2（不同源端口）
	a.Feed(mkPkt(ipB, ipA, 53, 5353, 17, 70, 20, base)) // ID 3

	flows := a.Flows()
	if len(flows) != 3 {
		t.Fatalf("len(Flows()) = %d, want 3", len(flows))
	}
	for i, f := range flows {
		if f.ID != uint64(i+1) {
			t.Errorf("flows[%d].ID = %d, want %d", i, f.ID, i+1)
		}
	}

	// 修改返回的切片不影响内部状态。
	flows[0] = nil
	again := a.Flows()
	if len(again) != 3 || again[0] == nil {
		t.Errorf("Flows() copy semantics broken: %v", again)
	}

	// nil 接收者返回 nil。
	var nilA *Analyzer
	if got := nilA.Flows(); got != nil {
		t.Errorf("nil analyzer Flows() = %v, want nil", got)
	}
}
