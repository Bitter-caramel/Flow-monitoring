package datamodel

import "testing"

// fillSet 用容量为 cap 的数组调用 FillProtocols，返回去重后的集合与写入个数。
func fillSet(p *Packet, cap int) (map[string]bool, int) {
	buf := make([]string, cap)
	n := FillProtocols(p, buf)
	m := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		m[buf[i]] = true
	}
	return m, n
}

// a) IPProto=6 且 HTTP != nil → 集合恰为 {"tcp","http"}（顺序不限，且必须去重，故个数为 2）。
func TestFillProtocolsTCPHTTP(t *testing.T) {
	m, n := fillSet(&Packet{IPProto: 6, HTTP: &HTTP{}}, 8)
	if n != 2 || !m["tcp"] || !m["http"] || len(m) != 2 {
		t.Fatalf("IPProto=6+HTTP 应为 {tcp,http} 且去重, got n=%d m=%v", n, m)
	}
}

// b) IPProto=17 且 DNS != nil → 集合恰为 {"udp","dns"}。
func TestFillProtocolsUDPDNS(t *testing.T) {
	m, n := fillSet(&Packet{IPProto: 17, DNS: &DNS{}}, 8)
	if n != 2 || !m["udp"] || !m["dns"] || len(m) != 2 {
		t.Fatalf("IPProto=17+DNS 应为 {udp,dns}, got n=%d m=%v", n, m)
	}
}

// c) IPProto=1 与 IPProto=58 都应只得到 {"icmp"}。
func TestFillProtocolsICMP(t *testing.T) {
	for _, ip := range []uint8{1, 58} {
		m, n := fillSet(&Packet{IPProto: ip}, 8)
		if n != 1 || !m["icmp"] {
			t.Fatalf("IPProto=%d 应为 {icmp}, got n=%d m=%v", ip, n, m)
		}
	}
}

// d) TLS != nil 应含 "tls"；Proto == "SSH" 应含 "ssh"。
func TestFillProtocolsTLSAndSSH(t *testing.T) {
	if m, n := fillSet(&Packet{TLS: &TLS{}}, 8); n != 1 || !m["tls"] {
		t.Fatalf("TLS != nil 应含 tls, got n=%d m=%v", n, m)
	}
	if m, n := fillSet(&Packet{Proto: "SSH"}, 8); n != 1 || !m["ssh"] {
		t.Fatalf("Proto=SSH 应含 ssh, got n=%d m=%v", n, m)
	}
}

// e) 零值 Packet → 返回 0（不属于任何已知协议）。
func TestFillProtocolsZeroPacket(t *testing.T) {
	if _, n := fillSet(&Packet{}, 8); n != 0 {
		t.Fatalf("零值 Packet 应返回 0, got=%d", n)
	}
}

// f) p == nil → 返回 0。
func TestFillProtocolsNilPacket(t *testing.T) {
	buf := make([]string, 8)
	if n := FillProtocols(nil, buf); n != 0 {
		t.Fatalf("nil Packet 应返回 0, got=%d", n)
	}
}

// g) dst 太小时不能越界 panic，返回个数不超过 len(dst)。
func TestFillProtocolsSmallDst(t *testing.T) {
	p := &Packet{IPProto: 6, HTTP: &HTTP{}}
	buf := make([]string, 1)
	n := FillProtocols(p, buf)
	if n != 1 {
		t.Fatalf("len(dst)=1 时应写入 1 个, got=%d", n)
	}
	// len(dst)==0 也必须安全返回 0。
	if n := FillProtocols(p, nil); n != 0 {
		t.Fatalf("len(dst)=0 应返回 0, got=%d", n)
	}
}
