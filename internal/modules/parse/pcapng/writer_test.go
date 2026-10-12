package pcapng

import (
	"bytes"
	"testing"
	"time"
)

// 往返测试：写 3 个包（含非 4 倍数长度以验证 padding、含一个零值时间戳），
// 必须能被本包 reader 原样读回。
func TestWriterRoundTrip(t *testing.T) {
	const linkType = 1
	const snaplen = 0

	inputs := []struct {
		ts   time.Time
		data []byte
	}{
		{time.Date(2023, 5, 17, 12, 34, 56, 789012000, time.UTC), []byte("0123456789abcde")}, // 15 字节，长度非 4 倍数
		{time.Date(2024, 1, 2, 3, 4, 5, 6000, time.UTC), []byte{0xde, 0xad, 0xbe, 0xef}},     // 4 字节
		{time.Time{}, []byte{0x42}}, // 零值时间戳
	}

	var buf bytes.Buffer
	w, err := NewWriter(&buf, linkType, snaplen)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for i, in := range inputs {
		if err := w.WritePacket(in.ts, in.data); err != nil {
			t.Fatalf("WritePacket[%d]: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	c, err := Parse(buf.Bytes(), 0)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(c.Packets) != len(inputs) {
		t.Fatalf("包数 = %d, 期望 %d", len(c.Packets), len(inputs))
	}
	if c.LinkType != linkType {
		t.Errorf("链路类型 = %d, 期望 %d", c.LinkType, linkType)
	}
	if c.SnapLen != snaplen {
		t.Errorf("snaplen = %d, 期望 %d", c.SnapLen, snaplen)
	}
	// reader 把 shb_userappl（选项码 optUserAppl）落到 Capture.Meta.App。
	if got := c.Meta.App; got != shbUserApplVal {
		t.Errorf("shb_userappl(Meta.App) = %q, 期望 %q", got, shbUserApplVal)
	}

	for i, in := range inputs {
		p := c.Packets[i]
		if !bytes.Equal(p.Data, in.data) {
			t.Errorf("包 %d 帧字节不一致: got %x, want %x", i, p.Data, in.data)
		}
		if in.ts.IsZero() {
			if p.Sec != 0 || p.Usec != 0 {
				t.Errorf("包 %d 零值时间戳应写 0, got sec=%d usec=%d", i, p.Sec, p.Usec)
			}
			continue
		}
		// 时间戳精度为微秒：按微秒比较即"完全相等"。
		if p.Time.UnixMicro() != in.ts.UnixMicro() {
			t.Errorf("包 %d 时间戳不一致: got %v, want %v", i, p.Time, in.ts)
		}
	}
}

// snaplen 截断测试：snaplen=20 写一个 60 字节的包，读回捕获长度 20、原始长度 60。
func TestWriterSnaplenTruncate(t *testing.T) {
	data := make([]byte, 60)
	for i := range data {
		data[i] = byte(i)
	}

	var buf bytes.Buffer
	w, err := NewWriter(&buf, 1, 20)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.WritePacket(time.Unix(1700000000, 0), data); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	c, err := Parse(buf.Bytes(), 0)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(c.Packets) != 1 {
		t.Fatalf("包数 = %d, 期望 1", len(c.Packets))
	}
	if c.SnapLen != 20 {
		t.Errorf("snaplen = %d, 期望 20", c.SnapLen)
	}
	p := c.Packets[0]
	if p.CapLen != 20 {
		t.Errorf("捕获长度 = %d, 期望 20", p.CapLen)
	}
	if p.OrigLen != 60 {
		t.Errorf("原始长度 = %d, 期望 60", p.OrigLen)
	}
	if !bytes.Equal(p.Data, data[:20]) {
		t.Errorf("截断数据不一致: got %x, want %x", p.Data, data[:20])
	}
}

// 空段测试：不写任何包，只 NewWriter + Close，Parse 不应报错且包数为 0。
func TestWriterEmpty(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, 1, 0)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	c, err := Parse(buf.Bytes(), 0)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(c.Packets) != 0 {
		t.Fatalf("包数 = %d, 期望 0", len(c.Packets))
	}
	if len(c.Warns) != 0 {
		t.Errorf("解析出现告警: %v", c.Warns)
	}
}

// BytesWritten 测试：随写入单调增长，且 Close 后等于产出的总字节数。
func TestWriterBytesWritten(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, 1, 0)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	prev := w.BytesWritten()
	if prev <= 0 {
		t.Fatalf("构造后 BytesWritten = %d, 期望 > 0 (SHB+IDB)", prev)
	}

	for i := 0; i < 5; i++ {
		if err := w.WritePacket(time.Unix(1700000000+int64(i), int64(i)*1000), []byte{0, 1, 2, 3, 4}); err != nil {
			t.Fatalf("WritePacket[%d]: %v", i, err)
		}
		cur := w.BytesWritten()
		if cur <= prev {
			t.Fatalf("BytesWritten 未随写入增长: %d -> %d", prev, cur)
		}
		prev = cur
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got, want := w.BytesWritten(), int64(buf.Len()); got != want {
		t.Errorf("BytesWritten = %d, 实际产出字节数 = %d", got, want)
	}
}
