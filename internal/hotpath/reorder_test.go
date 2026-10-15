package hotpath

// reorder_test.go —— 乱序 / 带洞 的端到端回归（任务 11-6）。
//
// 端到端链路照 golden_test.go 的 runGolden：把程序化构造的 Ethernet+IPv4+TCP 帧用
// pcapng.NewWriter 写成临时夹具（t.TempDir()，绝不提交进仓库），再
// os.ReadFile → pcapng.Parse → decoder.Decode → hp.Process，把命中规范成
// `No=<PktNo> sid=<RuleID> buf=<Buffer> off=<Offset>` 的行集合。
//
// ★ 实测（2026-10-14）：
//   - 乱序（[0,10) 先到、[20,30) 早于 [10,20) 到达）与顺序夹具的命中集合**完全相同**
//     （重组器把洞之后的字节暂存、待补齐后连续交付，视图在同样的包号上非空）。
//   - 带洞夹具补洞前匹配不到跨洞完整串（只有前缀命中），补上缺失段后立刻能匹配整串。
//
// ★ 说明为何乱序夹具用 "SYN,A,C,B"（A=[1001,1011)、B=[1011,1021) 洞、C=[1021,1031)）：
//   实测 gopacket Assembler 对「落在 nextSeq 之前」的段按 overlap 丢弃。若在高序号段
//   之后才收到最低段，最低段会被丢弃（实测 [C,A,B] 会丢 A）。先发 A 再让 C 早于 B 到达，
//   才既能真正乱序、又保证重组完整。SYN 建立基准序号，与真实 TCP 流一致。

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"flow-monitoring/internal/modules/detect"
	"flow-monitoring/internal/modules/parse/decoder"
	"flow-monitoring/internal/modules/parse/pcapng"
)

// tcpFrame 序列化一个 Ethernet+IPv4+TCP 帧（与 reassembly 单测同一五元组）。
func tcpFrame(t *testing.T, seq uint32, syn bool, payload string) []byte {
	t.Helper()
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: src.To4(), DstIP: dst.To4()}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: 80, Seq: seq, DataOffset: 5, Window: 65535, SYN: syn, ACK: !syn, PSH: !syn}
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
		eth, ip, tcp, gopacket.Payload([]byte(payload))); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

// writeFixture 把 frames 依次写进 dir/name.pcapng（linkType=1 Ethernet），返回路径。
func writeFixture(t *testing.T, dir, name string, frames [][]byte) string {
	t.Helper()
	path := filepath.Join(dir, name+".pcapng")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("创建夹具失败: %v", err)
	}
	w, err := pcapng.NewWriter(f, 1, 0)
	if err != nil {
		f.Close()
		t.Fatalf("NewWriter: %v", err)
	}
	for i, fr := range frames {
		if err := w.WritePacket(time.Unix(int64(i+1), 0), fr); err != nil {
			t.Fatalf("WritePacket(%d): %v", i+1, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close file: %v", err)
	}
	return path
}

// runFixture 走生产真路径跑夹具，返回规范化的命中行（保留包序）。
func runFixture(t *testing.T, rulesSrc, fixturePath string) []string {
	t.Helper()
	rs := detect.LoadText(rulesSrc)
	if rs == nil {
		t.Fatalf("LoadText 返回 nil")
	}
	hp := New(rs)
	defer hp.Close()

	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("读取夹具失败: %v", err)
	}
	cap, err := pcapng.Parse(data, 0)
	if err != nil {
		t.Fatalf("解析 pcapng 失败: %v", err)
	}
	var lines []string
	for _, p := range cap.Packets {
		if p == nil {
			continue
		}
		linkType := cap.LinkType
		if p.Iface >= 0 && p.Iface < len(cap.Ifaces) {
			linkType = cap.Ifaces[p.Iface].LinkType
		}
		decoder.Decode(p, linkType)
		for _, a := range hp.Process(p) {
			lines = append(lines, fmt.Sprintf("No=%d sid=%s buf=%s off=%d", a.PktNo, a.RuleID, a.Buffer, a.Offset))
		}
	}
	return lines
}

// sortedStrings 返回排序后的拷贝（集合比较用）。
func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// sameSet 判断两个行集合是否完全相同（忽略顺序）。
func sameSet(a, b []string) bool {
	sa, sb := sortedStrings(a), sortedStrings(b)
	if len(sa) != len(sb) {
		return false
	}
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}

// containsLine 判断行是否在集合里。
func containsLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// TestReorderHitsIdentical：乱序夹具的命中集合必须与顺序夹具**完全相同**。
//
// 规则用 stream; pcre:"/./"（默认缓冲即 stream，这里显式写出）。若两者不同，说明
// "乱序会影响检测结果"，应当停下报告，而不是放宽断言。
func TestReorderHitsIdentical(t *testing.T) {
	// ★ 缓冲关键字写在 pcre 之前。
	const rules = `alert tcp any any -> any any (msg:"x"; stream; pcre:"/./"; sid:970001;)`

	syn := tcpFrame(t, 1000, true, "")
	a := tcpFrame(t, 1001, false, "AAAA") // [1001,1011)
	b := tcpFrame(t, 1005, false, "BBBB") // [1005,1009) 中间的段
	c := tcpFrame(t, 1009, false, "CCCC") // [1009,1013)

	dir := t.TempDir()
	orderedPath := writeFixture(t, dir, "ordered", [][]byte{syn, a, b, c})
	reorderPath := writeFixture(t, dir, "reorder", [][]byte{syn, a, c, b}) // C 早于 B 到达（乱序）

	ordered := runFixture(t, rules, orderedPath)
	reorder := runFixture(t, rules, reorderPath)

	t.Logf("顺序夹具命中(%d 行): %v", len(ordered), ordered)
	t.Logf("乱序夹具命中(%d 行): %v", len(reorder), reorder)

	if len(ordered) == 0 {
		t.Fatalf("顺序夹具不应零命中（否则比较无意义）")
	}
	if !sameSet(ordered, reorder) {
		t.Fatalf("乱序命中集合 != 顺序命中集合：\n 顺序=%v\n 乱序=%v", ordered, reorder)
	}
}

// TestGapDelaysThenMatches：带洞夹具在补洞前只能命中"前缀"，补上缺失段后从补洞那个包
// 开始能命中跨洞的完整字节序列。
//
// 负载 "AAAABBBBCCCC" 被拆成 A="AAAA"、B="BBBB"、C="CCCC"，夹具里先只写 A 和 C
// （洞挖掉 B），随后在第 4 个包补上 B。规则：
//   - sid 970011 匹配前缀 "/AAAA/"（补洞前后都应命中）；
//   - sid 970012 匹配跨洞完整串 "/AAAABBBBCCCC/"（只有补洞后才命中）。
func TestGapDelaysThenMatches(t *testing.T) {
	const rules = `alert tcp any any -> any any (msg:"pre"; stream; pcre:"/AAAA/"; sid:970011;)
alert tcp any any -> any any (msg:"full"; stream; pcre:"/AAAABBBBCCCC/"; sid:970012;)`

	syn := tcpFrame(t, 1000, true, "")
	a := tcpFrame(t, 1001, false, "AAAA") // [1001,1005)
	b := tcpFrame(t, 1005, false, "BBBB") // [1005,1009) 缺失段：最后补
	c := tcpFrame(t, 1009, false, "CCCC") // [1009,1013)

	dir := t.TempDir()
	gapPath := writeFixture(t, dir, "gap", [][]byte{syn, a, c})            // 带洞：缺 B
	fillPath := writeFixture(t, dir, "gap-filled", [][]byte{syn, a, c, b}) // 第 4 个包补上 B

	before := runFixture(t, rules, gapPath)
	after := runFixture(t, rules, fillPath)

	t.Logf("补洞前命中(%d 行): %v", len(before), before)
	t.Logf("补洞后命中(%d 行): %v", len(after), after)

	// 跨洞完整规则在补洞前必须一条都不命中。
	var fullBefore, fullAfter []string
	for _, l := range before {
		if strings.Contains(l, "sid=suricata-970012") {
			fullBefore = append(fullBefore, l)
		}
	}
	for _, l := range after {
		if strings.Contains(l, "sid=suricata-970012") {
			fullAfter = append(fullAfter, l)
		}
	}
	t.Logf("补洞前跨洞完整规则(sid 970012)命中: %v", fullBefore)
	t.Logf("补洞后跨洞完整规则(sid 970012)命中: %v", fullAfter)

	if len(fullBefore) != 0 {
		t.Fatalf("补洞前不应命中跨洞完整串：%v", fullBefore)
	}
	// 补洞的那个包是第 4 个；从它开始能匹配补齐后的完整内容（offset=0）。
	const wantFull = "No=4 sid=suricata-970012 buf=stream off=0"
	if !containsLine(fullAfter, wantFull) {
		t.Fatalf("补洞后跨洞命中缺 %q：实际 %v", wantFull, fullAfter)
	}

	// "补洞前的命中集合是缺一部分的"：补洞前集合必须是补洞后集合的真子集。
	for _, l := range before {
		if !containsLine(after, l) {
			t.Fatalf("补洞前命中 %q 不在补洞后集合中：after=%v", l, after)
		}
	}
	if len(after) <= len(before) {
		t.Fatalf("补洞后应有新增命中：before=%d 行 after=%d 行", len(before), len(after))
	}
}

// TestMidstreamReorderStillMatchedByPayload：中途抓包（无 SYN）+ 乱序 ⇒ C′（窄口径防漏）生效。
//
// 夹具 [C, A, B]（★ 故意不写 SYN，否则不是中途流，C′ 不触发）：
//
//	C=[1013,1019)="CCCCCC" 先到 ⇒ 把重组基准钉在 1013；
//	A=[1001,1007)="AAAAAA"、B=[1007,1013)="BBBBBB" 都落在基准之前 ⇒ 段永久搁浅，
//	重组视图里只剩 C 的 "CCCCCC"。
//
// 规则 `stream; pcre:"/AAAAAA/"`：
//   - ★ 接通检测侧之前这条测试是红的：A 包的 stream 视图只有 "CCCCCC"，匹配不到 "AAAAAA"；
//   - 接通后：C′ 让承载搁浅段的 A 包回落 payload（"AAAAAA"）⇒ 命中；C 包用 stream（只有
//     "CCCCCC"）不命中；B 包回落 payload（"BBBBBB"）也不命中 ⇒ 恰好 1 次，命中 A 包。
//
// ★ 为什么载荷用 6 字节而不是 4 字节：以太网帧最小 60 字节，4 字节载荷只有 58 字节 ⇒
// 序列化时尾部会补 2 字节零（真实网卡同样会补）⇒ 会踩到 decoder 的 payloadOffset 缺陷
// （`decoder/layers.go` 用 `len(Data)-len(payload)` 从帧尾反算 ⇒ 有填充时偏移偏大，见 12.x）。
// 6 字节载荷让帧恰好 60 字节、不带填充，从而**只验证 C′ 本身**（该 decoder 缺陷另开任务修）。
func TestMidstreamReorderStillMatchedByPayload(t *testing.T) {
	const rules = `alert tcp any any -> any any (msg:"x"; stream; pcre:"/AAAAAA/"; sid:970021;)`

	c := tcpFrame(t, 1013, false, "CCCCCC") // [1013,1019)：先到，钉住基准
	a := tcpFrame(t, 1001, false, "AAAAAA") // [1001,1007)：落在基准之前
	b := tcpFrame(t, 1007, false, "BBBBBB") // [1007,1013)：落在基准之前

	dir := t.TempDir()
	path := writeFixture(t, dir, "midstream-reorder", [][]byte{c, a, b})
	hits := runFixture(t, rules, path)

	t.Logf("中途乱序命中(%d 行): %v", len(hits), hits)
	if len(hits) != 1 {
		t.Fatalf("应恰好命中 1 次（A 包回落 payload），实际 %d 行: %v", len(hits), hits)
	}
	const want = "No=2 sid=suricata-970021 buf=stream off=0"
	if !containsLine(hits, want) {
		t.Fatalf("应命中 A 包 %q，实际 %v", want, hits)
	}
}
