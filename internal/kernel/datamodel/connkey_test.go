package datamodel

import "testing"

// TestConnKeySymmetric 守住对称性：交换两端必须得到同一个键，
// 否则同一条连接会被拆成两个组。
func TestConnKeySymmetric(t *testing.T) {
	a := ConnKey("10.0.0.1", 1234, "10.0.0.2", 80)
	b := ConnKey("10.0.0.2", 80, "10.0.0.1", 1234)
	if a != b {
		t.Fatalf("ConnKey not symmetric: %q != %q", a, b)
	}
	if a == "" {
		t.Fatalf("ConnKey returned empty for valid endpoints")
	}
}

// TestConnKeyDistinct 守住不同连接不同键：换端口或换 IP 都必须变。
func TestConnKeyDistinct(t *testing.T) {
	base := ConnKey("10.0.0.1", 1234, "10.0.0.2", 80)

	cases := []struct {
		name             string
		srcIP, dstIP     string
		srcPort, dstPort uint16
	}{
		{"src port changed", "10.0.0.1", "10.0.0.2", 1235, 80},
		{"dst port changed", "10.0.0.1", "10.0.0.2", 1234, 81},
		{"src ip changed", "10.0.0.9", "10.0.0.2", 1234, 80},
		{"dst ip changed", "10.0.0.1", "10.0.0.3", 1234, 80},
	}
	for _, c := range cases {
		if got := ConnKey(c.srcIP, c.srcPort, c.dstIP, c.dstPort); got == base {
			t.Fatalf("%s: ConnKey = %q, want different from %q", c.name, got, base)
		}
	}
}

// TestConnKeyIPv6Symmetric 守住 IPv6 也能对称（原样拼接、不加方括号）。
func TestConnKeyIPv6Symmetric(t *testing.T) {
	a := ConnKey("2408::1", 443, "2408::2", 39912)
	b := ConnKey("2408::2", 39912, "2408::1", 443)
	if a != b {
		t.Fatalf("IPv6 ConnKey not symmetric: %q != %q", a, b)
	}
	if a != "2408::1:443|2408::2:39912" {
		t.Fatalf("IPv6 ConnKey = %q, want %q", a, "2408::1:443|2408::2:39912")
	}
}

// TestConnKeyOf 守住 ConnKeyOf 的 nil 安全与方向无关性。
func TestConnKeyOf(t *testing.T) {
	if got := ConnKeyOf(nil); got != "" {
		t.Fatalf("ConnKeyOf(nil) = %q, want %q", got, "")
	}

	p := &Packet{SrcIP: "10.0.0.1", SrcPort: 1234, DstIP: "10.0.0.2", DstPort: 80}
	k1 := ConnKeyOf(p)
	if k1 == "" {
		t.Fatalf("ConnKeyOf(packet) = %q, want non-empty", k1)
	}

	// 交换两端（模拟反方向包）应得到同一个键。
	rev := &Packet{SrcIP: p.DstIP, SrcPort: p.DstPort, DstIP: p.SrcIP, DstPort: p.SrcPort}
	k2 := ConnKeyOf(rev)
	if k1 != k2 {
		t.Fatalf("ConnKeyOf reverse direction = %q, want %q", k2, k1)
	}
}
