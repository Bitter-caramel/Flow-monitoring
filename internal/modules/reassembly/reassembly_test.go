package reassembly

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"flow-monitoring/internal/kernel/datamodel"
)

// 测试用的固定五元组：A=10.0.0.1（低地址），B=10.0.0.2（高地址）。
const (
	testSrcPort = 40000
	testDstPort = 80
)

var (
	testSrc = net.IPv4(10, 0, 0, 1)
	testDst = net.IPv4(10, 0, 0, 2)
)

type tcpFlags struct {
	syn, ack, fin, rst, psh bool
}

// buildTCPPacket 用 gopacket 序列化出真实帧（Ethernet+IPv4+TCP），再填 datamodel.Packet。
// ★ 必须走真实字节：重组器要从帧里解出 TCP 序号，不真实经过 gopacket 就等于没测重组。
func buildTCPPacket(t *testing.T, srcIP, dstIP net.IP, srcPort, dstPort uint16, seq uint32, fl tcpFlags, payload []byte) *datamodel.Packet {
	t.Helper()

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP.To4(),
		DstIP:    dstIP.To4(),
	}
	tcp := &layers.TCP{
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		Seq:        seq,
		DataOffset: 5,
		Window:     65535,
		SYN:        fl.syn,
		ACK:        fl.ack,
		FIN:        fl.fin,
		RST:        fl.rst,
		PSH:        fl.psh,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
		EthernetType: layers.EthernetTypeIPv4,
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	data := append([]byte(nil), buf.Bytes()...)

	p := &datamodel.Packet{
		Data:       data,
		IPVersion:  4,
		IPProto:    6,
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SrcIP:      srcIP.String(),
		DstIP:      dstIP.String(),
		SrcIPNum:   binary.BigEndian.Uint32(srcIP.To4()),
		DstIPNum:   binary.BigEndian.Uint32(dstIP.To4()),
		PayloadLen: len(payload),
		StreamID:   -1,
	}
	p.PayloadOff = len(data) - len(payload)
	return p
}

// 一个应用层载荷拆成两个 TCP 段，依次喂入后 View 的对应方向应拼出完整载荷。
func TestFeedSplitSegmentAcrossPackets(t *testing.T) {
	r := New(DefaultOptions())
	defer r.Close()

	full := []byte("GET /admin HTTP/1.1\r\nHost: victim\r\n\r\n")
	cut := 9
	p1 := buildTCPPacket(t, testSrc, testDst, testSrcPort, testDstPort, 1001, tcpFlags{ack: true, psh: true}, full[:cut])
	p2 := buildTCPPacket(t, testSrc, testDst, testSrcPort, testDstPort, 1001+uint32(cut), tcpFlags{ack: true, psh: true}, full[cut:])

	r.Feed(p1)
	r.Feed(p2)

	v := r.View(p1)
	if got := v.BytesToServer(); !bytes.Equal(got, full) {
		t.Fatalf("BytesToServer = %q, want %q", got, full)
	}
	if got := v.BytesToClient(); got != nil {
		t.Fatalf("BytesToClient = %q, want nil", got)
	}
	if r.FlowCount() != 1 {
		t.Fatalf("FlowCount = %d, want 1", r.FlowCount())
	}
}

// 乱序：先喂后段、再喂前段，仍应按序号拼回正确顺序。
// 先给一个 SYN 建立基准序号，再乱序喂两个数据段（gopacket 需要基准序号）。
func TestOutOfOrder(t *testing.T) {
	r := New(DefaultOptions())
	defer r.Close()

	syn := buildTCPPacket(t, testSrc, testDst, testSrcPort, testDstPort, 5000, tcpFlags{syn: true}, nil)
	first := buildTCPPacket(t, testSrc, testDst, testSrcPort, testDstPort, 5001, tcpFlags{ack: true, psh: true}, []byte("AAAA"))
	second := buildTCPPacket(t, testSrc, testDst, testSrcPort, testDstPort, 5005, tcpFlags{ack: true, psh: true}, []byte("BBBB"))

	r.Feed(syn)
	r.Feed(second) // 后段先到
	r.Feed(first)  // 前段后到

	want := []byte("AAAABBBB")
	if got := r.View(first).BytesToServer(); !bytes.Equal(got, want) {
		t.Fatalf("BytesToServer = %q, want %q", got, want)
	}
}

// MaxStreamBytes 设得很小：应停止追加并置 Truncated，且之后不再增长。
func TestMaxStreamBytesTruncates(t *testing.T) {
	opts := DefaultOptions()
	opts.MaxStreamBytes = 4
	r := New(opts)
	defer r.Close()

	p1 := buildTCPPacket(t, testSrc, testDst, testSrcPort, testDstPort, 100, tcpFlags{ack: true, psh: true}, []byte("0123456789"))
	p1.StreamID = 1
	r.Feed(p1)

	if got := r.View(p1).BytesToServer(); string(got) != "0123" {
		t.Fatalf("BytesToServer = %q, want %q", got, "0123")
	}
	st, ok := r.StatsOf(1, ToServer)
	if !ok {
		t.Fatalf("StatsOf 未命中流 1")
	}
	if !st.Truncated || st.Bytes != 4 {
		t.Fatalf("StatsOf = %+v, want Truncated=true Bytes=4", st)
	}

	// 后续段必须不再增长。
	p2 := buildTCPPacket(t, testSrc, testDst, testSrcPort, testDstPort, 110, tcpFlags{ack: true, psh: true}, []byte("abcdefghij"))
	p2.StreamID = 1
	r.Feed(p2)
	if got := r.View(p1).BytesToServer(); len(got) != 4 {
		t.Fatalf("截断后仍增长：len=%d want=4", len(got))
	}
}

// MemCap 设得很小、喂多个流：Bytes() 不得超上限（允许按 LRU 淘汰）。
func TestMemCapEvicts(t *testing.T) {
	opts := DefaultOptions()
	opts.MemCap = 16
	r := New(opts)
	defer r.Close()

	for i := 0; i < 6; i++ {
		src := net.IPv4(10, 0, 0, byte(i+1))
		payload := bytes.Repeat([]byte{byte('a' + i)}, 8)
		p := buildTCPPacket(t, src, testDst, uint16(2000+i), testDstPort, 1, tcpFlags{ack: true, psh: true}, payload)
		r.Feed(p)
	}

	if r.Bytes() > opts.MemCap {
		t.Fatalf("Bytes() = %d, 超上限 %d", r.Bytes(), opts.MemCap)
	}
	if r.Bytes() <= 0 {
		t.Fatalf("Bytes() = %d, 期望在淘汰后仍有数据", r.Bytes())
	}
}

// Skip=true：Feed/View 都安全且不产生任何数据。
func TestSkip(t *testing.T) {
	opts := DefaultOptions()
	opts.Skip = true
	r := New(opts)
	defer r.Close()

	p := buildTCPPacket(t, testSrc, testDst, testSrcPort, testDstPort, 1, tcpFlags{ack: true, psh: true}, []byte("data"))
	r.Feed(p)

	v := r.View(p)
	if v.BytesToServer() != nil || v.BytesToClient() != nil {
		t.Fatalf("Skip 模式下不应有流数据")
	}
	if r.FlowCount() != 0 || r.Bytes() != 0 {
		t.Fatalf("Skip 模式 FlowCount=%d Bytes=%d, want 0/0", r.FlowCount(), r.Bytes())
	}
}

// 非 TCP（UDP/ICMP/垃圾字节）与 nil 包：不 panic、不产生流。
func TestNonTCPIgnored(t *testing.T) {
	r := New(DefaultOptions())
	defer r.Close()

	r.Feed(nil) // 必须不 panic

	udp := &datamodel.Packet{IPVersion: 4, IPProto: 17, SrcPort: 53, DstPort: 5353, StreamID: -1, Data: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}}
	r.Feed(udp)

	icmp := &datamodel.Packet{IPVersion: 4, IPProto: 1, StreamID: -1}
	r.Feed(icmp)

	garbage := &datamodel.Packet{IPVersion: 4, IPProto: 6, StreamID: -1, Data: []byte{0xde, 0xad, 0xbe, 0xef}}
	r.Feed(garbage)

	if r.FlowCount() != 0 {
		t.Fatalf("FlowCount = %d, want 0", r.FlowCount())
	}
	if v := r.View(udp); v.BytesToServer() != nil || v.BytesToClient() != nil {
		t.Fatalf("非 TCP 包不应有流视图数据")
	}
}

// 对从未喂过的包调 View：两个方法都返回 nil，绝不 panic。
func TestViewNeverPanics(t *testing.T) {
	r := New(DefaultOptions())
	defer r.Close()

	p := buildTCPPacket(t, testSrc, testDst, testSrcPort, testDstPort, 1, tcpFlags{ack: true, psh: true}, []byte("x"))

	v := r.View(p)
	if v.BytesToServer() != nil || v.BytesToClient() != nil {
		t.Fatalf("未喂过的包不应有数据")
	}
	if v := r.View(nil); v.BytesToServer() != nil || v.BytesToClient() != nil {
		t.Fatalf("View(nil) 应返回空视图")
	}
}

// 反方向（B→A）的数据应落在 BytesToClient，且不影响 to_server。
func TestReverseDirection(t *testing.T) {
	r := New(DefaultOptions())
	defer r.Close()

	req := buildTCPPacket(t, testSrc, testDst, testSrcPort, testDstPort, 1, tcpFlags{ack: true, psh: true}, []byte("REQ"))
	resp := buildTCPPacket(t, testDst, testSrc, testDstPort, testSrcPort, 1, tcpFlags{ack: true, psh: true}, []byte("RESP"))

	r.Feed(req)
	r.Feed(resp)

	if got := r.View(req).BytesToServer(); string(got) != "REQ" {
		t.Fatalf("BytesToServer = %q, want REQ", got)
	}
	if got := r.View(resp).BytesToClient(); string(got) != "RESP" {
		t.Fatalf("BytesToClient = %q, want RESP", got)
	}
}
