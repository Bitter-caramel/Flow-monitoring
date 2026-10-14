package hotpath

import (
	"os"
	"path/filepath"
	"testing"

	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/modules/detect"
	"flow-monitoring/internal/modules/parse/decoder"
	"flow-monitoring/internal/modules/parse/pcapng"
	"flow-monitoring/internal/modules/rule"
)

// TestNewSkipsReassemblyWhenUnused 验证 11-4 的"跳过优化"：
// 规则集里没有任何条件引用 stream 缓冲时，New 不应建重组器。
func TestNewSkipsReassemblyWhenUnused(t *testing.T) {
	rs := detect.LoadText(`alert tcp any any -> any any (msg:"x"; pcre:"/./"; sid:950001;)`)
	hp := New(rs)
	defer hp.Close()
	if hp.Reassembles() {
		t.Fatal("裸规则（未引用 stream）不应建重组器，Reassembles() 应为 false")
	}
}

// TestNewBuildsReassemblyWhenStreamUsed 验证：显式引用 stream 缓冲时应当建重组器。
func TestNewBuildsReassemblyWhenStreamUsed(t *testing.T) {
	// ★ 缓冲关键字必须写在 pcre 之前，否则会被当成 pcre 的一部分。
	rs := detect.LoadText(`alert tcp any any -> any any (msg:"x"; stream; pcre:"/./"; sid:950002;)`)
	hp := New(rs)
	defer hp.Close()
	if !hp.Reassembles() {
		t.Fatal("引用 stream 的规则应建重组器，Reassembles() 应为 true")
	}
}

// TestProcessNilSafe 验证 Process / Analyzer 在 nil 入参下不 panic。
func TestProcessNilSafe(t *testing.T) {
	if got := New(nil).Process(&datamodel.Packet{}); got != nil {
		t.Fatalf("New(nil).Process 应返回 nil，得到 %v", got)
	}
	var h *Hotpath
	if got := h.Process(&datamodel.Packet{}); got != nil {
		t.Fatalf("nil *Hotpath 的 Process 应返回 nil，得到 %v", got)
	}
	if got := New(nil).Analyzer(); got == nil {
		t.Fatal("New(nil).Analyzer() 不应为 nil")
	}
	// p 为 nil 同样应安全返回 nil。
	rs := detect.LoadText(`alert tcp any any -> any any (msg:"x"; pcre:"/./"; sid:950003;)`)
	if got := New(rs).Process(nil); got != nil {
		t.Fatalf("p 为 nil 时 Process 应返回 nil，得到 %v", got)
	}
}

// TestProcessFeedsReassemblyBeforeMatch 是「顺序红线」的守卫：
// 若把重组器 Feed 与引擎 Match 的顺序写反，当包将看不到自己那段流，本测试变红。
func TestProcessFeedsReassemblyBeforeMatch(t *testing.T) {
	rs := detect.LoadText(`alert tcp any any -> any any (msg:"x"; stream; pcre:"/./"; sid:950002;)`)
	hp := New(rs)
	defer hp.Close()
	if !hp.Reassembles() {
		t.Fatal("stream 规则集应建重组器")
	}

	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "test.pcapng"))
	if err != nil {
		t.Fatalf("读取样本文件失败: %v", err)
	}
	cap, err := pcapng.Parse(data, 0)
	if err != nil {
		t.Fatalf("解析 pcapng 失败: %v", err)
	}
	if len(cap.Packets) == 0 {
		t.Fatal("样本中没有数据包")
	}

	total, streamHits := 0, 0
	for _, p := range cap.Packets {
		if p == nil {
			continue
		}
		linkType := cap.LinkType
		if p.Iface >= 0 && p.Iface < len(cap.Ifaces) {
			linkType = cap.Ifaces[p.Iface].LinkType
		}
		decoder.Decode(p, linkType)
		for _, h := range hp.Process(p) {
			total++
			if h.Buffer == rule.BufStream {
				streamHits++
			}
		}
	}
	t.Logf("实际观测：总命中 %d，其中 Buffer==stream 命中 %d", total, streamHits)
	if streamHits == 0 {
		t.Fatalf("没有任何命中的 Buffer==stream（总命中 %d）：Feed 与 Match 的顺序可能被写反", total)
	}
}
