package pcapng

import (
	"os"
	"path/filepath"
	"testing"

	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/modules/parse/decoder"
)

// TestParse_Offsets C2：解析器必须为每个包记录「包数据起点」的绝对偏移，
// 且用该偏移切出的字节能被 decoder 解出一个完整包（不能只做算术断言）。
func TestParse_Offsets(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "testdata", "attacks", "sqli.pcapng")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 sqli.pcapng: %v", err)
	}

	c, err := Parse(data, 0)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(c.Packets) == 0 {
		t.Fatal("未解析出任何包")
	}

	// 所有包都要有有效偏移，且 Offset+CapLen 不越过文件末尾。
	for i, p := range c.Packets {
		if p.Offset <= 0 {
			t.Errorf("packet[%d].Offset = %d, want > 0", i, p.Offset)
		}
		if p.CapLen <= 0 {
			t.Errorf("packet[%d].CapLen = %d, want > 0", i, p.CapLen)
		}
		if p.Offset+p.CapLen > len(data) {
			t.Errorf("packet[%d] 越界: Offset=%d CapLen=%d fileLen=%d", i, p.Offset, p.CapLen, len(data))
		}
		if int(p.DataOff) != p.Offset {
			t.Errorf("packet[%d].DataOff(%d) != Offset(%d)", i, p.DataOff, p.Offset)
		}
	}

	first := c.Packets[0]
	if first.Offset <= 0 {
		t.Fatalf("第 1 包 Offset = %d, want > 0", first.Offset)
	}

	// ★ 关键验证：Offset 指向的字节必须能被 decoder 解出一个完整包。
	raw := data[first.Offset : first.Offset+first.CapLen]
	q := datamodel.NewPacket()
	q.No = first.No
	q.CapLen = first.CapLen
	q.OrigLen = first.OrigLen
	q.Data = raw
	decoder.Decode(q, c.LinkType)
	if q.Malformed {
		t.Fatalf("用 Offset 切出的字节解码失败（Malformed），Offset=%d CapLen=%d", first.Offset, first.CapLen)
	}
	if q.SrcIP == "" || q.DstIP == "" {
		t.Errorf("解码后 IP 为空: Src=%q Dst=%q", q.SrcIP, q.DstIP)
	}
	if q.Proto == "" || q.Proto == "?" {
		t.Errorf("解码后 Proto 未识别: %q", q.Proto)
	}
	if q.SrcMAC == "" || q.DstMAC == "" {
		t.Errorf("解码后 MAC 为空: %q / %q", q.SrcMAC, q.DstMAC)
	}

	t.Logf("sqli.pcapng 第 1 包: Offset=%d CapLen=%d Proto=%s SrcIP=%s DstIP=%s",
		first.Offset, first.CapLen, q.Proto, q.SrcIP, q.DstIP)
}
