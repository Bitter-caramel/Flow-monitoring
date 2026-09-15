package decoder

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"

	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/modules/parse/pcapng"
)

// 构造帧辅助函数

func ethFrame(etherType uint16, payload []byte) []byte {
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) // dst
	copy(frame[6:12], net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) // src
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[14:], payload)
	return frame
}

func ipv4Packet(proto uint8, srcIP, dstIP net.IP, payload []byte) []byte {
	totalLen := 20 + len(payload)
	hdr := make([]byte, 20)
	hdr[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(hdr[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(hdr[4:6], 0x1234) // id
	hdr[8] = 64                                   // ttl
	hdr[9] = proto
	copy(hdr[12:16], srcIP.To4())
	copy(hdr[16:20], dstIP.To4())
	return append(hdr, payload...)
}

func tcpSegment(srcPort, dstPort uint16, flags byte, seq, ack uint32, payload []byte) []byte {
	seg := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(seg[0:2], srcPort)
	binary.BigEndian.PutUint16(seg[2:4], dstPort)
	binary.BigEndian.PutUint32(seg[4:8], seq)
	binary.BigEndian.PutUint32(seg[8:12], ack)
	seg[12] = 0x50 // data offset 20 字节
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:16], 65535)
	copy(seg[20:], payload)
	return seg
}

func udpSegment(srcPort, dstPort uint16, payload []byte) []byte {
	seg := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(seg[0:2], srcPort)
	binary.BigEndian.PutUint16(seg[2:4], dstPort)
	binary.BigEndian.PutUint16(seg[4:6], uint16(8+len(payload)))
	copy(seg[8:], payload)
	return seg
}

func newPacket(data []byte) *datamodel.Packet {
	p := datamodel.NewPacket()
	p.Data = data
	p.CapLen = len(data)
	p.OrigLen = len(data)
	p.No = 1
	return p
}

// TestDecode_EthernetIPv4TCP 端到端 TCP 解码。
func TestDecode_EthernetIPv4TCP(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0x04} // 非 L7 数据，保持 TCP 判定
	frame := ethFrame(0x0800, ipv4Packet(6,
		net.ParseIP("192.168.1.100"),
		net.ParseIP("192.168.1.1"),
		tcpSegment(12345, 80, 0x02, 1000, 0, payload),
	))

	p := newPacket(frame)
	Decode(p, 1)

	if p.Proto != "TCP" {
		t.Errorf("Proto = %q, want TCP", p.Proto)
	}
	if p.SrcIP != "192.168.1.100" || p.DstIP != "192.168.1.1" {
		t.Errorf("IP = %s -> %s, want 192.168.1.100 -> 192.168.1.1", p.SrcIP, p.DstIP)
	}
	if p.SrcPort != 12345 || p.DstPort != 80 {
		t.Errorf("port = %d -> %d, want 12345 -> 80", p.SrcPort, p.DstPort)
	}
	if p.TCPFlags&0x02 == 0 {
		t.Error("SYN flag should be set")
	}
	if p.PayloadLen != len(payload) {
		t.Errorf("PayloadLen = %d, want %d", p.PayloadLen, len(payload))
	}
	if p.IPProto != 6 {
		t.Errorf("IPProto = %d, want 6", p.IPProto)
	}
	if p.SrcMAC == "" || p.DstMAC == "" {
		t.Error("MAC should be set")
	}
	if p.IPVersion != 4 {
		t.Errorf("IPVersion = %d, want 4", p.IPVersion)
	}
}

// TestDecode_EthernetIPv4UDP UDP 解码。
func TestDecode_EthernetIPv4UDP(t *testing.T) {
	payload := []byte{0x00, 0x01, 0x02, 0x03}
	frame := ethFrame(0x0800, ipv4Packet(17,
		net.ParseIP("10.0.0.1"),
		net.ParseIP("10.0.0.2"),
		udpSegment(1000, 2000, payload), // 非 L7 端口，保持 UDP 判定
	))

	p := newPacket(frame)
	Decode(p, 1)

	if p.Proto != "UDP" {
		t.Errorf("Proto = %q, want UDP", p.Proto)
	}
	if p.SrcPort != 1000 || p.DstPort != 2000 {
		t.Errorf("port = %d -> %d, want 1000 -> 2000", p.SrcPort, p.DstPort)
	}
	if p.PayloadLen != len(payload) {
		t.Errorf("PayloadLen = %d, want %d", p.PayloadLen, len(payload))
	}
}

// TestDecode_EthernetARP ARP 解码。
func TestDecode_EthernetARP(t *testing.T) {
	arp := make([]byte, 28)
	binary.BigEndian.PutUint16(arp[0:2], 1)     // hw type Ethernet
	binary.BigEndian.PutUint16(arp[2:4], 0x0800) // proto IPv4
	arp[4] = 6                                    // hw len
	arp[5] = 4                                    // proto len
	binary.BigEndian.PutUint16(arp[6:8], 1)     // request
	copy(arp[8:14], net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	copy(arp[14:18], net.ParseIP("192.168.1.1").To4())
	copy(arp[24:28], net.ParseIP("192.168.1.100").To4())

	frame := ethFrame(0x0806, arp)
	p := newPacket(frame)
	Decode(p, 1)

	if p.Proto != "ARP" {
		t.Errorf("Proto = %q, want ARP", p.Proto)
	}
	if p.ARP == nil {
		t.Fatal("ARP should not be nil")
	}
	if p.ARP.SenderIP != "192.168.1.1" {
		t.Errorf("SenderIP = %q, want 192.168.1.1", p.ARP.SenderIP)
	}
	if p.ARP.Opcode != 1 {
		t.Errorf("Opcode = %d, want 1", p.ARP.Opcode)
	}
}

// TestDecode_EthernetIPv4ICMP ICMP 解码。
func TestDecode_EthernetIPv4ICMP(t *testing.T) {
	icmpPayload := make([]byte, 8)
	icmpPayload[0] = 8 // Echo Request
	icmpPayload[1] = 0
	binary.BigEndian.PutUint16(icmpPayload[4:6], 0xbeef) // id
	binary.BigEndian.PutUint16(icmpPayload[6:8], 1)      // seq

	frame := ethFrame(0x0800, ipv4Packet(1,
		net.ParseIP("10.0.0.1"),
		net.ParseIP("10.0.0.2"),
		icmpPayload,
	))

	p := newPacket(frame)
	Decode(p, 1)

	if p.Proto != "ICMP" {
		t.Errorf("Proto = %q, want ICMP", p.Proto)
	}
	if p.ICMP == nil {
		t.Fatal("ICMP should not be nil")
	}
	if p.ICMP.Type != 8 || p.ICMP.ID != 0xbeef || p.ICMP.Seq != 1 {
		t.Errorf("ICMP = %+v, want Type=8 ID=0xbeef Seq=1", p.ICMP)
	}
}

// TestDecode_VLAN 802.1Q VLAN 递归展开。
func TestDecode_VLAN(t *testing.T) {
	innerIP := ipv4Packet(17,
		net.ParseIP("1.1.1.1"),
		net.ParseIP("2.2.2.2"),
		udpSegment(1000, 2000, []byte("data")),
	)

	// VLAN 帧：dst MAC(6) + src MAC(6) + TPID(2) + TCI(2) + 内层 EtherType(2) + IP
	outer := make([]byte, 0, 18+len(innerIP))
	outer = append(outer, net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}...)
	outer = append(outer, net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}...)
	tpid := make([]byte, 2)
	binary.BigEndian.PutUint16(tpid, 0x8100) // VLAN TPID
	outer = append(outer, tpid...)
	tci := make([]byte, 2)
	binary.BigEndian.PutUint16(tci, 100) // VLAN ID 100
	outer = append(outer, tci...)
	innerType := make([]byte, 2)
	binary.BigEndian.PutUint16(innerType, 0x0800) // 内层 IPv4
	outer = append(outer, innerType...)
	outer = append(outer, innerIP...)

	p := newPacket(outer)
	Decode(p, 1)

	if p.Proto != "UDP" {
		t.Errorf("Proto = %q, want UDP (through VLAN)", p.Proto)
	}
	if p.SrcIP != "1.1.1.1" {
		t.Errorf("SrcIP = %q, want 1.1.1.1", p.SrcIP)
	}
}

// TestDecode_Malformed 畸形包不 panic，标记 Malformed。
func TestDecode_Malformed(t *testing.T) {
	// 声明为 IPv4 但数据太短
	p := newPacket([]byte{0x45, 0x00})
	Decode(p, 1)
	// 不应 panic；Proto 可能为空或被兜底
	_ = p.Proto
}

// TestDecode_TestPcapng 集成：解析真实样本并解码所有包。
func TestDecode_TestPcapng(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "testdata", "test.pcapng")
	abs, _ := filepath.Abs(path)
	data, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	cap, err := pcapng.Parse(data, 0)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	decoded := 0
	for _, p := range cap.Packets {
		linkType := cap.LinkType
		if p.Iface >= 0 && p.Iface < len(cap.Ifaces) {
			linkType = cap.Ifaces[p.Iface].LinkType
		}
		Decode(p, linkType)
		if p.Proto != "" {
			decoded++
		}
	}
	if decoded == 0 {
		t.Error("no packet decoded with a protocol")
	}
	t.Logf("decoded %d/%d packets with protocol", decoded, len(cap.Packets))
}
