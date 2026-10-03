package analyzer

import (
	"testing"
	"time"

	"flow-monitoring/internal/kernel/datamodel"
)

// mkTCPPkt 构造一个带序号与 TCP 标志位的 IPv4 TCP 包（复用 mkPkt）。
func mkTCPPkt(src, dst uint32, sp, dp uint16, no int, flags uint16, ts time.Time) *datamodel.Packet {
	p := mkPkt(src, dst, sp, dp, 6, 60, 0, ts)
	p.No = no
	p.TCPFlags = flags
	return p
}

// TCP 标志位（与 tcp.go 保持一致）。
const (
	tFIN uint16 = 0x01
	tSYN uint16 = 0x02
	tRST uint16 = 0x04
	tACK uint16 = 0x10
)

// TestAnalyzerTCP_SynNotEstablished 覆盖纯 SYN 只记录 SynNo、不置 Established。
func TestAnalyzerTCP_SynNotEstablished(t *testing.T) {
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	a := New()

	a.Feed(mkTCPPkt(ipA, ipB, 1234, 80, 1, tSYN, base))

	f := a.Flow(ipA, 1234, ipB, 80, 6)
	if f == nil {
		t.Fatalf("Flow(ipA,1234,ipB,80,6) = nil, want non-nil")
	}
	if f.State != datamodel.FlowUnknown {
		t.Errorf("State = %v, want FlowUnknown（纯 SYN 不应置 Established）", f.State)
	}
	if f.State == datamodel.FlowEstablished {
		t.Errorf("State = FlowEstablished, want not Established")
	}
	if f.SynNo != 1 {
		t.Errorf("SynNo = %d, want 1", f.SynNo)
	}

	// 重复 SYN（重传）只记录首个包号。
	a.Feed(mkTCPPkt(ipA, ipB, 1234, 80, 2, tSYN, base.Add(time.Second)))
	if f.SynNo != 1 {
		t.Errorf("SynNo after retransmit = %d, want 1（仅首次）", f.SynNo)
	}
	if f.State != datamodel.FlowUnknown {
		t.Errorf("State after retransmit = %v, want FlowUnknown", f.State)
	}
}

// TestAnalyzerTCP_SynAckEstablishes 覆盖 SYN+ACK 置 Established 并记录 SynAckNo。
func TestAnalyzerTCP_SynAckEstablishes(t *testing.T) {
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	a := New()

	a.Feed(mkTCPPkt(ipA, ipB, 1234, 80, 1, tSYN, base))
	a.Feed(mkTCPPkt(ipB, ipA, 80, 1234, 2, tSYN|tACK, base.Add(time.Millisecond)))
	a.Feed(mkTCPPkt(ipA, ipB, 1234, 80, 3, tACK, base.Add(2*time.Millisecond)))

	f := a.Flow(ipA, 1234, ipB, 80, 6)
	if f == nil {
		t.Fatalf("Flow(ipA,1234,ipB,80,6) = nil, want non-nil")
	}
	if f.State != datamodel.FlowEstablished {
		t.Errorf("State = %v, want FlowEstablished", f.State)
	}
	if f.SynAckNo != 2 {
		t.Errorf("SynAckNo = %d, want 2", f.SynAckNo)
	}
}

// TestAnalyzerTCP_RstResets 覆盖 RST 置 Reset 并记录 RstNo。
func TestAnalyzerTCP_RstResets(t *testing.T) {
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	a := New()

	a.Feed(mkTCPPkt(ipA, ipB, 1234, 80, 1, tSYN, base))
	a.Feed(mkTCPPkt(ipB, ipA, 80, 1234, 2, tSYN|tACK, base.Add(time.Millisecond)))
	a.Feed(mkTCPPkt(ipA, ipB, 1234, 80, 3, tRST|tACK, base.Add(2*time.Millisecond)))

	f := a.Flow(ipA, 1234, ipB, 80, 6)
	if f == nil {
		t.Fatalf("Flow(ipA,1234,ipB,80,6) = nil, want non-nil")
	}
	if f.State != datamodel.FlowReset {
		t.Errorf("State = %v, want FlowReset", f.State)
	}
	if f.RstNo != 3 {
		t.Errorf("RstNo = %d, want 3", f.RstNo)
	}
}

// TestAnalyzerTCP_FinHalfCloseThenClosed 覆盖单边 FIN=HalfClose、双边 FIN=Closed。
func TestAnalyzerTCP_FinHalfCloseThenClosed(t *testing.T) {
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	a := New()

	a.Feed(mkTCPPkt(ipA, ipB, 1234, 80, 1, tSYN, base))
	a.Feed(mkTCPPkt(ipB, ipA, 80, 1234, 2, tSYN|tACK, base.Add(time.Millisecond)))

	// A→B FIN：单边 -> HalfClose。
	a.Feed(mkTCPPkt(ipA, ipB, 1234, 80, 3, tFIN|tACK, base.Add(2*time.Millisecond)))
	f := a.Flow(ipA, 1234, ipB, 80, 6)
	if f == nil {
		t.Fatalf("Flow(ipA,1234,ipB,80,6) = nil, want non-nil")
	}
	if f.State != datamodel.FlowHalfClose {
		t.Errorf("State after single FIN = %v, want FlowHalfClose", f.State)
	}
	if f.FinDirs != 0x01 {
		t.Errorf("FinDirs after A→B FIN = %d, want 1", f.FinDirs)
	}

	// B→A FIN：双边 -> Closed。
	a.Feed(mkTCPPkt(ipB, ipA, 80, 1234, 4, tFIN|tACK, base.Add(3*time.Millisecond)))
	if f.State != datamodel.FlowClosed {
		t.Errorf("State after both FIN = %v, want FlowClosed", f.State)
	}
	if f.FinDirs != 0x03 {
		t.Errorf("FinDirs after both FIN = %d, want 3", f.FinDirs)
	}
}

// TestAnalyzerTCP_ReverseFinFirst 覆盖先 B→A FIN 的方向位与状态。
func TestAnalyzerTCP_ReverseFinFirst(t *testing.T) {
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	a := New()

	a.Feed(mkTCPPkt(ipB, ipA, 80, 1234, 1, tFIN, base))

	f := a.Flow(ipA, 1234, ipB, 80, 6)
	if f == nil {
		t.Fatalf("Flow(ipA,1234,ipB,80,6) = nil, want non-nil")
	}
	if f.State != datamodel.FlowHalfClose {
		t.Errorf("State = %v, want FlowHalfClose", f.State)
	}
	if f.FinDirs != 0x02 {
		t.Errorf("FinDirs = %d, want 2（bit1=B→A）", f.FinDirs)
	}
}

// TestAnalyzerTCP_UDPUnaffected 覆盖 UDP 包不进入 TCP 状态机、State 保持 Unknown。
func TestAnalyzerTCP_UDPUnaffected(t *testing.T) {
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	a := New()

	a.Feed(mkPkt(ipA, ipB, 5353, 53, 17, 70, 20, base))

	f := a.Flow(ipA, 5353, ipB, 53, 17)
	if f == nil {
		t.Fatalf("UDP flow lookup = nil, want non-nil")
	}
	if f.State != datamodel.FlowUnknown {
		t.Errorf("UDP State = %v, want FlowUnknown", f.State)
	}
	if f.FinDirs != 0 || f.SynNo != 0 || f.SynAckNo != 0 || f.RstNo != 0 {
		t.Errorf("UDP flow state fields = (%d,%d,%d,%d), want all zero",
			f.FinDirs, f.SynNo, f.SynAckNo, f.RstNo)
	}
}
