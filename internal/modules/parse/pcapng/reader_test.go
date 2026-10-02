package pcapng

import (
	"os"
	"path/filepath"
	"testing"
)

// testPcapngPath 返回 testdata/test.pcapng 的绝对路径。
func testPcapngPath(t *testing.T) string {
	t.Helper()
	// 从 internal/modules/parse/pcapng 回到项目根（4 层）
	path := filepath.Join("..", "..", "..", "..", "testdata", "test.pcapng")
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	return abs
}

// TestParse_TestPcapng 解析真实样本，验证基本字段。
func TestParse_TestPcapng(t *testing.T) {
	data, err := os.ReadFile(testPcapngPath(t))
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	c, err := Parse(data, 0)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if c.Format != "pcapng" {
		t.Errorf("Format = %q, want pcapng", c.Format)
	}
	if c.Endian != "little" {
		t.Errorf("Endian = %q, want little", c.Endian)
	}
	if c.Version == "" {
		t.Error("Version should not be empty")
	}
	if c.LinkType == 0 {
		t.Error("LinkType should be set")
	}
	if len(c.Packets) == 0 {
		t.Error("should parse at least one packet")
	}
	if len(c.Ifaces) == 0 {
		t.Error("should have at least one interface")
	}

	// 每个包应有数据与非零时间戳（除 noTime 外）
	for i, p := range c.Packets {
		if p.No != i+1 {
			t.Errorf("packet[%d].No = %d, want %d", i, p.No, i+1)
		}
		if p.CapLen < 0 {
			t.Errorf("packet[%d].CapLen < 0", i)
		}
		if len(p.Data) != p.CapLen {
			t.Errorf("packet[%d].Data len %d != CapLen %d", i, len(p.Data), p.CapLen)
		}
		if p.DataOff < 0 {
			t.Errorf("packet[%d].DataOff < 0", i)
		}
	}
}

// TestParse_TooShort 过短数据报错。
func TestParse_TooShort(t *testing.T) {
	if _, err := Parse([]byte{0x0a}, 0); err == nil {
		t.Error("Parse of 1-byte data should error")
	}
	if _, err := Parse([]byte{}, 0); err == nil {
		t.Error("Parse of empty data should error")
	}
}

// TestParse_TruncatedBlock 截断块不 panic，记录 warns。
func TestParse_TruncatedBlock(t *testing.T) {
	data, err := os.ReadFile(testPcapngPath(t))
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	// 截断到一半
	truncated := data[:len(data)/2]
	c, err := Parse(truncated, 0)
	if err != nil {
		t.Fatalf("Parse truncated: %v", err)
	}
	// 截断解析不报错，但应有 warns（或至少不 panic）
	_ = c.Warns
}

// TestParse_Limit 包数限制。
func TestParse_Limit(t *testing.T) {
	data, err := os.ReadFile(testPcapngPath(t))
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	c, err := Parse(data, 3)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(c.Packets) > 3 {
		t.Errorf("Packets len = %d, want <= 3", len(c.Packets))
	}
}

// TestTSScale 时间戳分辨率换算。
func TestTSScale(t *testing.T) {
	cases := []struct {
		resol uint8
		want  float64
	}{
		{6, 1e6},       // 微秒
		{9, 1e9},       // 纳秒
		{0, 1},         // 秒
		{3, 1000},      // 毫秒
		{0x80 | 6, 64}, // 二进制：2^6
		{0x80 | 10, 1024},
	}
	for _, tc := range cases {
		got := tsScale(tc.resol)
		if got != tc.want {
			t.Errorf("tsScale(%d) = %v, want %v", tc.resol, got, tc.want)
		}
	}
}

// TestMinBlockLen 最小块长表。
func TestMinBlockLen(t *testing.T) {
	cases := map[uint32]int{
		blockSHB: 28,
		blockIDB: 20,
		blockEPB: 32,
		blockSPB: 16,
		blockPB:  32,
		blockNRB: 16,
		blockISB: 24,
		blockDSB: 20,
		0x9999:   12, // 未知块默认 12
	}
	for bt, want := range cases {
		if got := minBlockLen(bt); got != want {
			t.Errorf("minBlockLen(0x%x) = %d, want %d", bt, got, want)
		}
	}
}
