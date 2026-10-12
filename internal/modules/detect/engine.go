package detect

import (
	"bytes"
	"fmt"
	"time"

	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/modules/rule"
)

// Alert 一条命中的告警。
//
// P0 里它只在进程内返回（由 parse-cli 打印）；接事件总线是后续冷路径任务。
type Alert struct {
	RuleID   string
	Name     string // 规则的 msg
	Severity string
	Weight   int
	Time     time.Time // 取 Ctx.Pkt.Time
	SrcIP    string
	SrcPort  uint16
	DstIP    string
	DstPort  uint16
	Proto    string // Ctx.Pkt.Proto（展示名）
	StreamID int    // Ctx.Pkt.StreamID（-1 = 未归属）
	PktNo    int    // 包序号（来自 Packet.No，从 1 开始）；★“从告警跳回那个包”的关键
	FlowKey  string // 规范化五元组的可读形式，如 "10.0.0.5:50000->93.184.216.34:80/tcp"
	Buffer   rule.Buffer
	Offset   int    // 命中位置（相对该缓冲区）
	Snippet  string // 命中的那几字节（最多 64，避免告警过大）
}

// snippetMax 是 Alert.Snippet 的截断长度。
const snippetMax = 64

// Engine 是匹配执行器：只读输入，遍历候选规则并求值。
type Engine struct {
	progs    []*Program
	anyProto []*Program                   // Proto == rule.ProtoAny 的规则
	byProto  map[rule.Protocol][]*Program // 协议限定的规则
}

// NewEngine 建索引。nil / 空输入都要能正常工作。
func NewEngine(progs []*Program) *Engine {
	e := &Engine{byProto: make(map[rule.Protocol][]*Program)}
	for _, p := range progs {
		if p == nil {
			continue
		}
		e.progs = append(e.progs, p)
		if p.Proto == rule.ProtoAny {
			e.anyProto = append(e.anyProto, p)
			continue
		}
		e.byProto[p.Proto] = append(e.byProto[p.Proto], p)
	}
	return e
}

// RuleCount 返回索引里规则条数。
func (e *Engine) RuleCount() int {
	if e == nil {
		return 0
	}
	return len(e.progs)
}

// Match 返回全部命中的告警；无命中返回 nil。
//
// 候选规则分两段遍历（先 anyProto，再协议精确匹配），不做 append 拼切片。
//
// ★ 一个包可能同时属于多个协议（HTTP 跑在 TCP 上时集合是 {"tcp","http"}），
// 所以这里对「包所属协议集合」里的每个协议都去 byProto 里取候选规则 ——
// 规则里写 tcp 和写 http 都能命中同一个包。集合由 datamodel.FillProtocols
// 用栈数组（零分配）填出，禁止为了 range 再造切片。
func (e *Engine) Match(c *Ctx) []Alert {
	if e == nil || c == nil || c.Pkt == nil {
		return nil
	}
	var alerts []Alert
	for _, p := range e.anyProto {
		if p == nil {
			continue
		}
		if hit, buf, off := matchProgram(p, c); hit {
			alerts = append(alerts, buildAlert(p, c, buf, off))
		}
	}
	// 协议集合只可能有 tcp/udp/icmp 之一 + http/dns/tls/ssh，6 个槽位足够。
	var protos [6]string
	n := datamodel.FillProtocols(c.Pkt, protos[:])
	for i := 0; i < n; i++ {
		for _, p := range e.byProto[rule.Protocol(protos[i])] {
			if p == nil {
				continue
			}
			if hit, buf, off := matchProgram(p, c); hit {
				alerts = append(alerts, buildAlert(p, c, buf, off))
			}
		}
	}
	return alerts
}

// buildAlert 由命中信息构造告警（冷路径，命中才走）。
func buildAlert(p *Program, c *Ctx, buf rule.Buffer, off int) Alert {
	pkt := c.Pkt
	a := Alert{
		RuleID:   p.ID,
		Name:     p.Name,
		Severity: p.Severity,
		Weight:   p.Action.Weight,
		Time:     pkt.Time,
		SrcIP:    pkt.SrcIP,
		SrcPort:  pkt.SrcPort,
		DstIP:    pkt.DstIP,
		DstPort:  pkt.DstPort,
		Proto:    pkt.Proto,
		StreamID: pkt.StreamID,
		PktNo:    pkt.No,
		FlowKey:  fmt.Sprintf("%s:%d->%s:%d/%s", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, datamodel.TransportName(pkt.IPProto)),
		Buffer:   buf,
		Offset:   off,
	}
	if b := hitBuffer(p, c, buf); b != nil && off >= 0 && off < len(b) {
		end := off + snippetMax
		if end > len(b) {
			end = len(b)
		}
		a.Snippet = string(b[off:end])
	}
	return a
}

// hitBuffer 重新取出记录命中的那个缓冲区，只用于拼 Snippet。
// 同一个缓冲名对应的提取器是同一个函数，取任一条件即可。
func hitBuffer(p *Program, c *Ctx, buf rule.Buffer) []byte {
	for i := range p.Conds {
		if p.Conds[i].Buf == buf && p.Conds[i].Extract != nil {
			return p.Conds[i].Extract(c)
		}
	}
	return nil
}

// matchProgram 求值单条规则，返回是否命中以及命中所在的缓冲与偏移。
//
// 顺序严格照 docs/检测引擎.md §5：
//  1. 规则级 flow 筛选；
//  2. 源/目的端口分别筛选（★ 必须用 p.SrcPort / p.DstPort，不能用合并过的 AnyPort/Ports/Ranges）；
//  3. 条件按序求值（offset/depth 相对「上次匹配结束位置」）。
func matchProgram(p *Program, c *Ctx) (hit bool, buf rule.Buffer, off int) {
	if p == nil || c == nil || c.Pkt == nil {
		return false, "", 0
	}
	if !flowPass(p.Flow, c) {
		return false, "", 0
	}
	if !specMatch(p.SrcPort, c.Pkt.SrcPort) || !specMatch(p.DstPort, c.Pkt.DstPort) {
		return false, "", 0
	}

	last := 0 // 当前起点：第一条条件即缓冲起点
	var hitBuf rule.Buffer
	hitOff := 0
	recorded := false

	for i := range p.Conds {
		cond := &p.Conds[i]
		b := cond.Extract(c)
		// §5.4：缓冲区不存在 → 整条规则不匹配（取反也一样判不匹配）。
		if b == nil {
			return false, "", 0
		}
		start := last + cond.Offset
		if start < 0 || start > len(b) {
			return false, "", 0
		}
		end := len(b)
		if cond.Depth > 0 {
			end = start + cond.Depth
			if end > len(b) {
				end = len(b)
			}
		}

		// 在 b[start:] 上搜索；命中起点相对 start 的偏移必须落在窗口 [0, end-start) 内。
		found := false
		i0 := -1
		matchLen := 0
		switch {
		case cond.Kind == rule.CondContent && len(cond.Lower) > 0:
			// nocase：编译期已预置小写模式，运行期就地折叠比较，零分配。
			i0 = indexFold(b[start:], cond.Lower)
			if i0 >= 0 {
				found = true
				matchLen = len(cond.Lower)
			}
		case cond.Kind == rule.CondContent:
			i0 = bytes.Index(b[start:], cond.Content)
			if i0 >= 0 {
				found = true
				matchLen = len(cond.Content)
			}
		case cond.Kind == rule.CondPCRE && cond.Regex != nil:
			if loc := cond.Regex.FindIndex(b[start:]); loc != nil {
				i0 = loc[0]
				matchLen = loc[1] - loc[0]
				found = true
			}
		default:
			// 未知 kind / pcre 缺正则 → 该条件不匹配。
			found = false
		}
		found = found && i0 >= 0 && i0 < end-start
		if cond.Negate {
			found = !found
		}
		if !found {
			return false, "", 0
		}
		if cond.Negate {
			// 取反通过：不推进 last。
			continue
		}
		last = start + i0 + matchLen
		if !recorded {
			hitBuf = cond.Buf
			hitOff = start + i0
			recorded = true
		}
	}
	return true, hitBuf, hitOff
}

// flowPass 规则级 flow 筛选（§5.5）。
//
// ★ to_server / from_client 在 P0 不做筛选（analyzer 还没有「哪一侧是服务端」的语义，
// 不知道就不猜），这里直接放过。
func flowPass(f rule.FlowSpec, c *Ctx) bool {
	switch f {
	case rule.FlowEstablished:
		if c.Flow == nil {
			return false
		}
		switch c.Flow.State {
		case datamodel.FlowEstablished, datamodel.FlowHalfClose, datamodel.FlowClosed:
			return true
		default:
			return false
		}
	default:
		// FlowStateless / FlowToServer / "" → 通过。
		return true
	}
}

// specMatch 判定单个端口的 PortSpec 是否命中 port。
func specMatch(spec rule.PortSpec, port uint16) bool {
	if spec.Any {
		return true
	}
	for _, p := range spec.Ports {
		if p == port {
			return true
		}
	}
	for _, r := range spec.Ranges {
		if port >= r.From && port <= r.To {
			return true
		}
	}
	return false
}

// indexFold 在 hay 里做 ASCII 大小写不敏感搜索，返回起始下标，找不到返回 -1。
//
// ★ 零分配：就地折叠比较，禁止 bytes.ToLower（那会每次分配）。
// 只处理 ASCII（'A'-'Z' → +32）；非 ASCII 字节按原样比较。
func indexFold(hay, lowerNeedle []byte) int {
	n := len(lowerNeedle)
	if n == 0 {
		return 0
	}
	if n > len(hay) {
		return -1
	}
	for i := 0; i+n <= len(hay); i++ {
		if asciiLower(hay[i]) != asciiLower(lowerNeedle[0]) {
			continue
		}
		j := 1
		for j < n && asciiLower(hay[i+j]) == asciiLower(lowerNeedle[j]) {
			j++
		}
		if j == n {
			return i
		}
	}
	return -1
}

// asciiLower 返回 b 的 ASCII 小写形式。
func asciiLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
