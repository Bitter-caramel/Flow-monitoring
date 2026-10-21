package reassembly

import (
	"bytes"
	"encoding/binary"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"

	"flow-monitoring/internal/kernel/datamodel"
)

// flushInterval 是机会式超时 Flush 的最小间隔（用「包时间」衡量，不是真实时钟）。
//
// 为什么需要它：Feed 是逐包热路径，每个包都对所有连接扫一遍做超时判定代价太高；
// 用「上次 Flush 的包时间 + 固定间隔」限频，既保证超时最终能被执行，又不拖慢热路径。
// 为什么不放进 Options：这是实现细节（扫描频率），不是用户可配置的资源红线。
const flushInterval = time.Second

// Reassembler 是 TCP 重组器：包装 gopacket 的 StreamPool + Assembler，
// 我们的 Stream 负责「数据存哪儿、存多少」。
//
// 零值不可用，请使用 New 构造。
// Feed/View 与 gopacket Assembler 一样，不做并发保护（调用方串行喂包）。
type Reassembler struct {
	opts Options
	pool *reassembly.StreamPool
	asm  *reassembly.Assembler

	byKey map[streamKey]*stream // gopacket 五元组 -> stream
	byID  map[int]*stream       // analyzer 的 StreamID -> stream

	totalBytes int64 // 所有方向缓冲的字节总量
	evictions  int64 // 因 MemCap 淘汰的流数（计数，供观测）
	closed     bool

	// lastFlush 是上一次机会式 Flush 时的「包时间」（★ 不是 time.Now()）。
	// 用它限频：两次 Flush 之间至少相隔 flushInterval，避免逐包全量扫描。
	// 零值表示「还没 Flush 过」。
	lastFlush time.Time

	// preBaseline 是「本包」标记：Feed 在装配之前清零；stream.Accept 遇到
	// 「落在重组基准之前」的段时置位；View 用它决定本次视图是否不可信（C′）。
	// Feed 与 View 是同一个包上顺序调用的（hotpath.Process：Feed → Match），
	// 所以它只对当前包有效，不会串到别的包。
	preBaseline bool

	// 复用解码层与 parser，避免逐包分配。
	// Feed 串行调用，与 gopacket Assembler 的并发约束一致，无需加锁。
	eth     layers.Ethernet
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	ethP    *gopacket.DecodingLayerParser
	ip4P    *gopacket.DecodingLayerParser
	ip6P    *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
}

// streamKey 是规范化五元组（只含 TCP）：A=低地址方向。
// IP 用 [16]byte 承载，兼容 IPv4（前 4 字节）与 IPv6。
type streamKey struct {
	aIP   [16]byte
	aPort uint16
	bIP   [16]byte
	bPort uint16
}

// asmContext 是 gopacket 要求的 AssemblerContext 最小实现。
type asmContext struct{ ci gopacket.CaptureInfo }

func (c asmContext) GetCaptureInfo() gopacket.CaptureInfo { return c.ci }

// New 构造一个重组器。对非正数的资源参数套用默认值，避免误配导致立即截断或空转。
func New(opts Options) *Reassembler {
	if opts.MemCap <= 0 {
		opts.MemCap = 64 << 20
	}
	if opts.FlowTimeout <= 0 {
		opts.FlowTimeout = 60 * time.Second
	}
	if opts.MaxStreamBytes <= 0 {
		opts.MaxStreamBytes = 1 << 20
	}

	r := &Reassembler{
		opts:  opts,
		byKey: make(map[streamKey]*stream),
		byID:  make(map[int]*stream),
	}
	if opts.Skip {
		return r
	}

	r.ethP = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &r.eth, &r.ip4, &r.ip6, &r.tcp)
	r.ip4P = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &r.ip4, &r.ip6, &r.tcp)
	r.ip6P = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &r.ip6, &r.ip4, &r.tcp)
	r.decoded = make([]gopacket.LayerType, 0, 8)

	r.pool = reassembly.NewStreamPool(streamFactory{r: r})
	r.asm = reassembly.NewAssembler(r.pool)

	// 资源红线：gopacket 的乱序缓冲（页缓存）默认无上限（0=不限），
	// 这里按 MemCap / MaxStreamBytes 给它也设上限，确保任何情况下都不无界增长。
	per := pagesFor(int64(opts.MaxStreamBytes))
	total := pagesFor(opts.MemCap)
	if total < per {
		total = per
	}
	r.asm.MaxBufferedPagesPerConnection = per
	r.asm.MaxBufferedPagesTotal = total
	return r
}

// pagesFor 把字节上限折算成 gopacket 的页数（页大小按 4 KiB 估）。
func pagesFor(n int64) int {
	p := int(n / 4096)
	if p < 1 {
		p = 1
	}
	return p
}

// Feed 把一个包喂给重组器（热路径逐包调用）。
//
// 只处理 TCP：从包的原始帧重新解出 TCP 层（拿到序号/标志），再交给 gopacket 的
// Assembler。非 TCP、未解码、p==nil 一律安全忽略（不 panic）。
//
// 必须在检测之前调用（否则当包看不到自己那段流）。
func (r *Reassembler) Feed(p *datamodel.Packet) {
	if r == nil || r.opts.Skip || r.closed || p == nil {
		return
	}
	tcp, netFlow, ok := r.decodeTCP(p)
	if !ok {
		return
	}
	// ★ preBaseline 是「本包」标记：Feed 在装配之前清掉。stream.Accept 遇到
	// 「落在重组基准之前」的段时置位；View 用它决定本次视图是否不可信。
	// Feed 与 View 是同一个包上顺序调用的（hotpath.Process：Feed → Match），
	// 所以这个标记只对当前包有效，不会串到别的包。
	r.preBaseline = false
	// ★ 必须把包的真实 CaptureInfo（尤其是 Timestamp=包时间 p.Time）传给 Assembler：
	// gopacket 用 ci.Timestamp 记录 half.lastSeen 与乱序页的 page.seen，
	// 超时 Flush 判定（FlushOptions.T）正是拿它来比较的。缺失则恒为零值，
	// Flush 会「看起来做了但根本没生效」。
	r.asm.AssembleWithContext(netFlow, tcp, asmContext{ci: gopacket.CaptureInfo{
		Timestamp:     p.Time,
		CaptureLength: len(p.Data),
		Length:        len(p.Data),
	}})
	// 机会式超时 Flush：喂完本包后，按包时间回收超出 FlowTimeout 仍没补齐的洞。
	r.flushExpired(p.Time)

	key, nd := keyFrom(netFlow.Src().Raw(), netFlow.Dst().Raw(), uint16(tcp.SrcPort), uint16(tcp.DstPort))

	// 给「没被归流」的包回写归一化方向。
	//
	// 为什么可以回写：keyFrom 用的归一化规则与 analyzer 完全一致（低地址为 A、
	// 地址相同比端口），nd 就是本包在该坐标下的方向；而 detect.extractStream
	// 用 p.StreamDir 选方向。analyzer 目前只归 IPv4，IPv6 的 StreamID 恒为 -1、
	// StreamDir 恒为 0，若不回写，IPv6 反向包也会被当成 A→B，方向就错了。
	//
	// 为什么只在 StreamID < 0 时回写：已被 analyzer 归流的包（StreamID >= 0）
	// 方向由 analyzer 决定，不动它就不会和 IPv4 的既有行为打架。
	if p.StreamID < 0 {
		p.StreamDir = nd
	}

	s := r.byKey[key]
	if s == nil {
		return
	}
	if p.StreamID >= 0 {
		s.streamID = p.StreamID
		r.byID[p.StreamID] = s
	}
}

// flushExpired 做「机会式超时 Flush」：把超过 FlowTimeout 仍未补齐的洞跳过交付，
// 让 ReassembledSG 收到 skip>0（Gaps/GapBytes 如实记账），并让洞之后的数据重新可见。
//
// ★ 为什么是「机会式」而不是后台定时器：本包与 gopacket Assembler 一样不做并发保护，
// 调用方串行 Feed；起后台 goroutine 会引入数据竞争，违反设计红线。
//
// ★ 时间基准必须是包时间 now=p.Time（不是 time.Now()）：离线回放时成千上万个包可能在
// 亚秒内跑完，若用真实时钟永远等不到超时，测试也会非确定。
//
// 限频：距上次 Flush 不足 flushInterval（包时间）就直接返回，避免逐包全量扫描。
//
// 语义（已用 gopacket 源码核实）：cutoff := now - FlowTimeout；gopacket 只把
// 「最早未补齐段的 seen 时间 < cutoff」的段跳过并交付；TC 留零 ⇒ 不关闭任何连接，
// 因此不会丢掉已累积的字节。
func (r *Reassembler) flushExpired(now time.Time) {
	if now.IsZero() {
		// SPB 等无时间戳包：没有可信的「现在」，无法做超时判定，跳过。
		return
	}
	if !r.lastFlush.IsZero() && now.Sub(r.lastFlush) < flushInterval {
		return
	}
	r.lastFlush = now
	// 只 Flush 不 Close：FlushOptions.TC 零值 ⇒ gopacket 的关闭条件是
	// conn.lastSeen().Before(TC)，恒为 false，所以没有任何连接会被关掉；
	// 用 T 把「seen < cutoff」的过期洞跳过交付。
	r.asm.FlushWithOptions(reassembly.FlushOptions{T: now.Add(-r.opts.FlowTimeout)})
}

// View 返回「这个包所在流」的流视图，形状与 detect.StreamView 一致。
//
// 优先用 analyzer 分配的 StreamID 定位；退化时用包自身的五元组定位。
// 无流数据时返回的视图两个方法都返回 nil（绝不 panic）。
func (r *Reassembler) View(p *datamodel.Packet) StreamView {
	if r == nil || r.opts.Skip || r.closed || p == nil {
		return emptyStreamView{}
	}
	if p.StreamID >= 0 {
		if s := r.byID[p.StreamID]; s != nil {
			return &streamView{s: s, midstream: s.unreliable || r.preBaseline}
		}
	}
	if k, ok := keyFromPacket(p); ok {
		if s := r.byKey[k]; s != nil {
			return &streamView{s: s, midstream: s.unreliable || r.preBaseline}
		}
	}
	return emptyStreamView{}
}

// FlowCount 返回当前仍在跟踪的流数量。
func (r *Reassembler) FlowCount() int {
	if r == nil {
		return 0
	}
	return len(r.byKey)
}

// Bytes 返回所有方向已重组字节的总量。
func (r *Reassembler) Bytes() int64 {
	if r == nil {
		return 0
	}
	return r.totalBytes
}

// StatsOf 返回指定流、指定方向的重组统计；流不存在返回 false。
func (r *Reassembler) StatsOf(streamID int, dir Direction) (StreamStats, bool) {
	if r == nil {
		return StreamStats{}, false
	}
	if dir != ToServer && dir != ToClient {
		return StreamStats{}, false
	}
	s := r.byID[streamID]
	if s == nil {
		return StreamStats{}, false
	}
	return s.stats[dir], true
}

// Close 释放所有流；幂等。
func (r *Reassembler) Close() {
	if r == nil || r.closed {
		return
	}
	r.closed = true
	for _, s := range r.byKey {
		for i := range s.buf {
			s.buf[i] = nil
		}
		s.evicted = true
	}
	r.byKey = make(map[streamKey]*stream)
	r.byID = make(map[int]*stream)
	r.totalBytes = 0
}

// appendData 把一个方向的新字节追加进缓冲。
//
// MaxStreamBytes 红线：超限只追加能容纳的部分并置 Truncated，
// 之后不再增长（不无界增长）。任何情况下都不 panic。
func (r *Reassembler) appendData(s *stream, nd uint8, data []byte) {
	if r.closed || s.evicted {
		return
	}
	max := r.opts.MaxStreamBytes
	cur := len(s.buf[nd])
	if cur >= max {
		s.stats[nd].Truncated = true
		return
	}
	room := max - cur
	add := data
	if len(add) > room {
		add = add[:room]
		s.stats[nd].Truncated = true
	}
	s.buf[nd] = append(s.buf[nd], add...)
	s.stats[nd].Bytes += int64(len(add))
	r.totalBytes += int64(len(add))
	s.lastActive = time.Now()
	r.enforceMemCap()
}

// enforceMemCap 在总量超限时按「最久未活动」淘汰流。
func (r *Reassembler) enforceMemCap() {
	if r.opts.MemCap <= 0 {
		return
	}
	for r.totalBytes > r.opts.MemCap {
		var oldest *stream
		for _, s := range r.byKey {
			if oldest == nil || s.lastActive.Before(oldest.lastActive) {
				oldest = s
			}
		}
		if oldest == nil {
			break
		}
		r.evict(oldest)
	}
}

// dropStream 把一条流从我们的表里摘掉并释放它的缓冲（幂等）。
//
// ★ 两个调用方：
//   - evict（MemCap 淘汰）—— 额外记一次 evictions；
//   - stream.ReassemblyComplete（gopacket 判定连接结束、FIN/RST/超时）—— 见 D：
//     以前我们只返回 true 让 gopacket 把连接移出池，**自己的 byKey/byID 却继续持有
//     已关闭的旧 stream**（陈旧引用 + 缓冲滞留，docs/已完成/TCP重组.md §7.3）。
//
// 只动我们自己的表与缓冲；gopacket 侧的移出由 ReassemblyComplete 的返回值负责。
func (r *Reassembler) dropStream(s *stream) {
	if r == nil || s == nil {
		return
	}
	for i := range s.buf {
		r.totalBytes -= int64(len(s.buf[i]))
		s.buf[i] = nil
	}
	s.stats[0] = StreamStats{}
	s.stats[1] = StreamStats{}
	s.evicted = true
	delete(r.byKey, s.key)
	if s.streamID >= 0 && r.byID[s.streamID] == s {
		delete(r.byID, s.streamID)
	}
}

// evict 淘汰一条流：摘掉并释放缓冲，另记一次淘汰计数。
func (r *Reassembler) evict(s *stream) {
	if s == nil {
		return
	}
	r.dropStream(s)
	r.evictions++
}

// decodeTCP 从包的原始帧里解出 TCP 层并构造 netFlow。
//
// 说明：datamodel.Packet 只存了显示用字段（端口/标志/IP），没有存 TCP 序号，
// 而 gopacket 的 Assembler 必须要序号才能重组，所以这里用 gopacket 重新解码
// 包帧（与解析器同一条解码路径）。依次尝试裸 IPv4/IPv6 与以太网起始层，
// 并用包里的端口/IP 做校验，避免误判。
func (r *Reassembler) decodeTCP(p *datamodel.Packet) (tcpOut *layers.TCP, flowOut gopacket.Flow, ok bool) {
	// gopacket 对畸形数据可能 panic（解析器同样用 recover 兜底），
	// 这里统一兜底为「忽略该包」，满足「未解码/非 TCP 安全忽略」的红线。
	defer func() {
		if recover() != nil {
			tcpOut, flowOut, ok = nil, gopacket.Flow{}, false
		}
	}()

	data := p.Data
	if len(data) == 0 {
		return nil, gopacket.Flow{}, false
	}

	starts := make([]*gopacket.DecodingLayerParser, 0, 3)
	if v := data[0] >> 4; v == 4 {
		starts = append(starts, r.ip4P)
	} else if v == 6 {
		starts = append(starts, r.ip6P)
	}
	starts = append(starts, r.ethP, r.ip4P, r.ip6P)

	for _, parser := range starts {
		r.decoded = r.decoded[:0]
		_ = parser.DecodeLayers(data, &r.decoded)
		var has4, has6, hasTCP bool
		for _, lt := range r.decoded {
			switch lt {
			case layers.LayerTypeIPv4:
				has4 = true
			case layers.LayerTypeIPv6:
				has6 = true
			case layers.LayerTypeTCP:
				hasTCP = true
			}
		}
		if !hasTCP {
			continue
		}
		if p.SrcPort != 0 || p.DstPort != 0 {
			if uint16(r.tcp.SrcPort) != p.SrcPort || uint16(r.tcp.DstPort) != p.DstPort {
				continue
			}
		}
		var netFlow gopacket.Flow
		switch {
		case has4:
			if p.SrcIPNum != 0 || p.DstIPNum != 0 {
				if !ipMatch(r.ip4.SrcIP, p.SrcIPNum) || !ipMatch(r.ip4.DstIP, p.DstIPNum) {
					continue
				}
			}
			netFlow = gopacket.NewFlow(layers.EndpointIPv4, r.ip4.SrcIP, r.ip4.DstIP)
		case has6:
			netFlow = gopacket.NewFlow(layers.EndpointIPv6, r.ip6.SrcIP, r.ip6.DstIP)
		default:
			continue
		}
		tcp := r.tcp // 值拷贝：r.tcp 会在下次解码时被复用
		return &tcp, netFlow, true
	}
	return nil, gopacket.Flow{}, false
}

// keyFrom 从「源/目的 IP 字节 + 端口」构造规范化 key，并返回首包的归一化方向。
func keyFrom(src, dst []byte, sp, dp uint16) (streamKey, uint8) {
	c := bytes.Compare(src, dst)
	if c < 0 || (c == 0 && sp <= dp) {
		return streamKey{aIP: ipTo16(src), aPort: sp, bIP: ipTo16(dst), bPort: dp}, 0
	}
	return streamKey{aIP: ipTo16(dst), aPort: dp, bIP: ipTo16(src), bPort: sp}, 1
}

// keyFromPacket 用 datamodel 的五元组字段构造 key（IPv4 与 IPv6）。
// 仅用于 View 的退化路径：IPProto 非 TCP 或五元组不可用时返回 false。
func keyFromPacket(p *datamodel.Packet) (streamKey, bool) {
	if p == nil || p.IPProto != 6 {
		return streamKey{}, false
	}
	// IPv6：用字符串地址解析出 16 字节裸地址，与 gopacket 的
	// EndpointIPv6.Raw()（16 字节）对齐。
	//
	// ★ 必须是「真 IPv6」：net.ParseIP("1.2.3.4") 会返回 16 字节的 v4-mapped
	// （To4() != nil）。若把 v4-mapped 当 IPv6 用，键会是 16 字节，和 gopacket
	// EndpointIPv4.Raw() 的 4 字节对不上，破坏 IPv4 回归。用 To4()==nil 排除。
	if p.IPVersion == 6 {
		src := net.ParseIP(p.SrcIP)
		dst := net.ParseIP(p.DstIP)
		if src == nil || dst == nil ||
			len(src) != net.IPv6len || len(dst) != net.IPv6len ||
			src.To4() != nil || dst.To4() != nil {
			return streamKey{}, false
		}
		k, _ := keyFrom(src, dst, p.SrcPort, p.DstPort)
		return k, true
	}
	// IPv4（及其它版本值）：保持原有逻辑，确保 IPv4 的键逐字节不变。
	if p.SrcIPNum == 0 && p.DstIPNum == 0 && p.SrcPort == 0 && p.DstPort == 0 {
		return streamKey{}, false
	}
	var src, dst [4]byte
	binary.BigEndian.PutUint32(src[:], p.SrcIPNum)
	binary.BigEndian.PutUint32(dst[:], p.DstIPNum)
	k, _ := keyFrom(src[:], dst[:], p.SrcPort, p.DstPort)
	return k, true
}

// ipTo16 把 IP 字节拷进定长数组，兼容 v4（前 4 字节）与 v6。
func ipTo16(b []byte) (out [16]byte) {
	copy(out[:], b)
	return
}

// ipMatch 判断 net.IP 是否等于给定的 IPv4 整数。
func ipMatch(ip net.IP, num uint32) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return binary.BigEndian.Uint32(v4) == num
}
