package analyzer

import (
	"testing"
	"time"
)

// TestStats_Protocol 覆盖协议统计：按 p.Proto 累加包数/字节数，
// L7 名（HTTP）与 L4 名（TCP）分开计，互不混入。
func TestStats_Protocol(t *testing.T) {
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	a := New()

	// HTTP over TCP：两包，记为 L7 名 HTTP。
	p1 := mkPkt(ipA, ipB, 1234, 80, 6, 100, 40, base)
	p1.Proto = "HTTP"
	p2 := mkPkt(ipA, ipB, 1234, 80, 6, 60, 0, base.Add(time.Second))
	p2.Proto = "HTTP"

	// 纯 TCP（未识别 L7）：一包，应独立于 HTTP。
	p3 := mkPkt(ipA, ipB, 1235, 443, 6, 52, 0, base.Add(2*time.Second))
	p3.Proto = "TCP"

	// UDP：一包，独立于 TCP。
	p4 := mkPkt(ipB, ipA, 53, 5353, 17, 70, 20, base.Add(3*time.Second))
	p4.Proto = "UDP"

	a.Feed(p1)
	a.Feed(p2)
	a.Feed(p3)
	a.Feed(p4)

	st := a.Stats()

	if got := st.Protocols["HTTP"]; got.Packets != 2 || got.Bytes != 160 {
		t.Errorf("HTTP stat = %+v, want {Packets:2 Bytes:160}", got)
	}
	if got := st.Protocols["TCP"]; got.Packets != 1 || got.Bytes != 52 {
		t.Errorf("TCP stat = %+v, want {Packets:1 Bytes:52}", got)
	}
	if got := st.Protocols["UDP"]; got.Packets != 1 || got.Bytes != 70 {
		t.Errorf("UDP stat = %+v, want {Packets:1 Bytes:70}", got)
	}
	// HTTP 与 TCP 必须是两条独立记录。
	if len(st.Protocols) != 3 {
		t.Errorf("len(Protocols) = %d, want 3: %+v", len(st.Protocols), st.Protocols)
	}
}

// TestStats_Endpoint 覆盖端点统计：同一 IP 对双向归并，
// 且不同端口/协议的多次会话都归并到同一条端点记录。
func TestStats_Endpoint(t *testing.T) {
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	a := New()

	// 会话 1：A→B 与 B→A（同一五元组双向）。
	a.Feed(mkPkt(ipA, ipB, 1234, 80, 6, 60, 0, base))
	a.Feed(mkPkt(ipB, ipA, 80, 1234, 6, 100, 0, base.Add(time.Second)))
	// 会话 2：同 IP 对但不同端口（1235->443）。
	a.Feed(mkPkt(ipA, ipB, 1235, 443, 6, 40, 0, base.Add(2*time.Second)))
	// 会话 3：同 IP 对、不同协议（UDP）。
	a.Feed(mkPkt(ipB, ipA, 443, 1235, 17, 20, 0, base.Add(3*time.Second)))

	st := a.Stats()

	// 只有一条端点记录（IP 对不区分端口/协议）。
	if len(st.Endpoints) != 1 {
		t.Fatalf("len(Endpoints) = %d, want 1: %+v", len(st.Endpoints), st.Endpoints)
	}
	ek := EndpointKey{A: ipA, B: ipB}
	es, ok := st.Endpoints[ek]
	if !ok {
		t.Fatalf("Endpoints[%+v] missing, got %+v", ek, st.Endpoints)
	}
	if es.A != ipA || es.B != ipB {
		t.Errorf("endpoint A/B = (%d,%d), want (%d,%d)", es.A, es.B, ipA, ipB)
	}
	if es.Packets != 4 {
		t.Errorf("endpoint Packets = %d, want 4（双向+多端口合并）", es.Packets)
	}
	if es.Bytes != 60+100+40+20 {
		t.Errorf("endpoint Bytes = %d, want %d", es.Bytes, 60+100+40+20)
	}
}

// TestStats_Ports 覆盖端口统计：源端口与目的端口都各计一次。
func TestStats_Ports(t *testing.T) {
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	a := New()

	// p1: 1234 -> 80   （src 1234, dst 80）
	// p2: 80 -> 1234   （src 80,   dst 1234）
	// p3: 1234 -> 80   （src 1234, dst 80）
	// 合计：1234 出现 3 次（p1 源、p2 目的、p3 源），80 出现 3 次。
	a.Feed(mkPkt(ipA, ipB, 1234, 80, 6, 60, 0, base))
	a.Feed(mkPkt(ipB, ipA, 80, 1234, 6, 100, 0, base.Add(time.Second)))
	a.Feed(mkPkt(ipA, ipB, 1234, 80, 6, 40, 0, base.Add(2*time.Second)))

	st := a.Stats()

	if got := st.Ports[1234]; got != 3 {
		t.Errorf("Ports[1234] = %d, want 3（源/目的都计入）", got)
	}
	if got := st.Ports[80]; got != 3 {
		t.Errorf("Ports[80] = %d, want 3（源/目的都计入）", got)
	}
	if len(st.Ports) != 2 {
		t.Errorf("len(Ports) = %d, want 2: %+v", len(st.Ports), st.Ports)
	}
}

// TestStats_SnapshotCopy 覆盖 Stats() 的副本语义：
// 修改返回的 map 不会影响聚合器内部状态。
func TestStats_SnapshotCopy(t *testing.T) {
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	a := New()

	p := mkPkt(ipA, ipB, 1234, 80, 6, 60, 0, base)
	p.Proto = "HTTP"
	a.Feed(p)

	ek := EndpointKey{A: ipA, B: ipB}
	st := a.Stats()

	// 篡改快照的各张 map。
	st.Protocols["HTTP"] = ProtoStat{Packets: 999, Bytes: 999}
	st.Protocols["INJECTED"] = ProtoStat{Packets: 7, Bytes: 7}
	st.Endpoints[ek] = EndpointStat{A: ipA, B: ipB, Packets: 999, Bytes: 999}
	st.Ports[80] = 999
	st.Ports[1234] = 999

	// 重新取快照，内部状态应保持不变。
	st2 := a.Stats()

	if got := st2.Protocols["HTTP"]; got.Packets != 1 || got.Bytes != 60 {
		t.Errorf("after mutation Protocols[HTTP] = %+v, want {Packets:1 Bytes:60}", got)
	}
	if _, ok := st2.Protocols["INJECTED"]; ok {
		t.Errorf("after mutation Protocols contains INJECTED: %+v", st2.Protocols)
	}
	if len(st2.Protocols) != 1 {
		t.Errorf("after mutation len(Protocols) = %d, want 1", len(st2.Protocols))
	}

	if got := st2.Endpoints[ek]; got.Packets != 1 || got.Bytes != 60 {
		t.Errorf("after mutation Endpoints[%+v] = %+v, want {Packets:1 Bytes:60}", ek, got)
	}
	if len(st2.Endpoints) != 1 {
		t.Errorf("after mutation len(Endpoints) = %d, want 1", len(st2.Endpoints))
	}

	if got := st2.Ports[80]; got != 1 {
		t.Errorf("after mutation Ports[80] = %d, want 1", got)
	}
	if got := st2.Ports[1234]; got != 1 {
		t.Errorf("after mutation Ports[1234] = %d, want 1", got)
	}
	if len(st2.Ports) != 2 {
		t.Errorf("after mutation len(Ports) = %d, want 2", len(st2.Ports))
	}
}

// TestStats_SkippedNotCounted 覆盖被 Feed 跳过的包（IPv6/ICMP/其它协议/nil）
// 不进入协议、端点、端口三类统计。
func TestStats_SkippedNotCounted(t *testing.T) {
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	a := New()

	// 先放一个合法 TCP 包作为基准。
	valid := mkPkt(ipA, ipB, 1234, 80, 6, 60, 0, base)
	valid.Proto = "TCP"
	a.Feed(valid)

	// ICMP（IPProto=1），协议名即便为 ICMP 也不应计入。
	icmp := mkPkt(ipA, ipB, 0, 0, 1, 80, 0, base)
	icmp.Proto = "ICMP"
	// IPv6：IPVersion=6，即便 IPProto=TCP 也应跳过。
	v6 := mkPkt(ipA, ipB, 1234, 80, 6, 999, 0, base)
	v6.IPVersion = 6
	v6.Proto = "TCP"
	// 其它 IP 协议号（GRE=47）。
	gre := mkPkt(ipA, ipB, 0, 0, 47, 120, 0, base)
	gre.Proto = "GRE"

	a.Feed(icmp)
	a.Feed(v6)
	a.Feed(gre)
	a.Feed(nil) // nil 不应 panic，也不应计数

	st := a.Stats()

	// 协议统计：只有基准 TCP 一条，且字节/包数未被污染。
	if got := st.Protocols["TCP"]; got.Packets != 1 || got.Bytes != 60 {
		t.Errorf("Protocols[TCP] = %+v, want {Packets:1 Bytes:60}", got)
	}
	for _, name := range []string{"ICMP", "GRE"} {
		if _, ok := st.Protocols[name]; ok {
			t.Errorf("skip packet leaked into Protocols[%q]: %+v", name, st.Protocols)
		}
	}
	if len(st.Protocols) != 1 {
		t.Errorf("len(Protocols) = %d, want 1: %+v", len(st.Protocols), st.Protocols)
	}

	// 端点统计：只统计基准包。
	ek := EndpointKey{A: ipA, B: ipB}
	if got := st.Endpoints[ek]; got.Packets != 1 || got.Bytes != 60 {
		t.Errorf("Endpoints[%+v] = %+v, want {Packets:1 Bytes:60}", ek, got)
	}
	if len(st.Endpoints) != 1 {
		t.Errorf("len(Endpoints) = %d, want 1: %+v", len(st.Endpoints), st.Endpoints)
	}

	// 端口统计：被跳过包的端口 0 不应出现；80/1234 各只有基准包的 1 次。
	if _, ok := st.Ports[0]; ok {
		t.Errorf("skip packet leaked into Ports[0]: %+v", st.Ports)
	}
	if got := st.Ports[80]; got != 1 {
		t.Errorf("Ports[80] = %d, want 1", got)
	}
	if got := st.Ports[1234]; got != 1 {
		t.Errorf("Ports[1234] = %d, want 1", got)
	}
	if len(st.Ports) != 2 {
		t.Errorf("len(Ports) = %d, want 2: %+v", len(st.Ports), st.Ports)
	}
}

// TestStats_NilAnalyzer 覆盖 nil 接收者 Stats() 返回零值且不 panic。
func TestStats_NilAnalyzer(t *testing.T) {
	var nilA *Analyzer

	st := nilA.Stats()
	if st.Protocols != nil || st.Endpoints != nil || st.Ports != nil {
		t.Errorf("nil analyzer Stats() = %+v, want zero-value Stats（各 map 为 nil）", st)
	}
}
