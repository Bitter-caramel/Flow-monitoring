package detect

import "flow-monitoring/internal/modules/rule"

// Extractor 缓冲区提取器：给定检测单元，返回该缓冲区的字节。
// ★ 返回 nil 表示「该缓冲区在当前单元里不存在」，不等于空缓冲区。
type Extractor func(*Ctx) []byte

// buffers 是缓冲区名 → 提取器的注册表。
// 只在启动期（init）写入、之后只读，因此不需要加锁。
var buffers = map[rule.Buffer]Extractor{}

// Register 注册一个缓冲区的提取器。
// 重复注册同一个缓冲区名会 panic —— 这属于编程错误，应当尽早暴露。
func Register(buf rule.Buffer, fn Extractor) {
	if _, ok := buffers[buf]; ok {
		panic("duplicate buffer: " + string(buf))
	}
	buffers[buf] = fn
}

// LookupBuffer 按缓冲区名查找提取器。
func LookupBuffer(buf rule.Buffer) (Extractor, bool) {
	fn, ok := buffers[buf]
	return fn, ok
}

func init() {
	Register(rule.BufPayload, extractPayload)
	Register(rule.BufHTTPHeader, extractHTTPHeader)
	Register(rule.BufHTTPClientBody, extractHTTPClientBody)
	Register(rule.BufHTTPURI, extractHTTPURI)
	Register(rule.BufHTTPMethod, extractHTTPMethod)
	Register(rule.BufDNSQuery, extractDNSQuery)
	Register(rule.BufTLSSNI, extractTLSSNI)
	Register(rule.BufStream, extractStream)
}

// 说明：下面所有「相对载荷」的偏移，都是相对 P.PayloadOff 而言的，
// 即 Packet.Data 中应用层载荷的起点为 po = P.PayloadOff。
// 所有切片上下界都必须先做越界检查，越界一律返回 nil（绝不 panic）；
// Ctx == nil 或 Pkt == nil 也一律返回 nil。

// extractPayload 返回整个应用层载荷：Data[po : po+PayloadLen]。
// 什么时候是 nil：Ctx/Pkt 为 nil；PayloadLen <= 0；po 为负；po+PayloadLen 超过 len(Data)。
func extractPayload(c *Ctx) []byte {
	if c == nil || c.Pkt == nil {
		return nil
	}
	p := c.Pkt
	po := p.PayloadOff
	n := p.PayloadLen
	if n <= 0 || po < 0 || po+n > len(p.Data) {
		return nil
	}
	return p.Data[po : po+n]
}

// extractHTTPHeader 返回 HTTP 头段：Data[po : po+HeaderLen]。
// 什么时候是 nil：Ctx/Pkt 为 nil；非 HTTP 包（P.HTTP == nil）；
// HeaderLen <= 0；po 为负；po+HeaderLen 超过 len(Data)。
func extractHTTPHeader(c *Ctx) []byte {
	if c == nil || c.Pkt == nil || c.Pkt.HTTP == nil {
		return nil
	}
	p := c.Pkt
	po := p.PayloadOff
	n := p.HTTP.HeaderLen
	if n <= 0 || po < 0 || po+n > len(p.Data) {
		return nil
	}
	return p.Data[po : po+n]
}

// extractHTTPClientBody 返回 HTTP 客户端正文：Data[po+BodyOff : po+PayloadLen]。
// 什么时候是 nil：Ctx/Pkt 为 nil；非 HTTP 包；BodyOff <= 0（0 = 未知/不存在正文）；
// BodyOff >= PayloadLen（正文起点不在载荷内）；po 为负；po+PayloadLen 超过 len(Data)。
func extractHTTPClientBody(c *Ctx) []byte {
	if c == nil || c.Pkt == nil || c.Pkt.HTTP == nil {
		return nil
	}
	p := c.Pkt
	po := p.PayloadOff
	off := p.HTTP.BodyOff
	end := p.PayloadLen
	if off <= 0 || off >= end || po < 0 || po+end > len(p.Data) {
		return nil
	}
	return p.Data[po+off : po+end]
}

// extractHTTPURI 返回 HTTP 请求 URI：Data[po+URIOff : po+URIOff+URILen]。
// 什么时候是 nil：Ctx/Pkt 为 nil；非 HTTP 包；URILen <= 0；
// 偏移为负；po+URIOff+URILen 超过 len(Data)。
func extractHTTPURI(c *Ctx) []byte {
	if c == nil || c.Pkt == nil || c.Pkt.HTTP == nil {
		return nil
	}
	p := c.Pkt
	po := p.PayloadOff
	off := p.HTTP.URIOff
	n := p.HTTP.URILen
	if n <= 0 || off < 0 || po < 0 || po+off+n > len(p.Data) {
		return nil
	}
	return p.Data[po+off : po+off+n]
}

// extractHTTPMethod 返回 HTTP 方法：Data[po+MethodOff : po+MethodOff+MethodLen]。
// 什么时候是 nil：Ctx/Pkt 为 nil；非 HTTP 包；MethodLen <= 0；
// 偏移为负；po+MethodOff+MethodLen 超过 len(Data)。
func extractHTTPMethod(c *Ctx) []byte {
	if c == nil || c.Pkt == nil || c.Pkt.HTTP == nil {
		return nil
	}
	p := c.Pkt
	po := p.PayloadOff
	off := p.HTTP.MethodOff
	n := p.HTTP.MethodLen
	if n <= 0 || off < 0 || po < 0 || po+off+n > len(p.Data) {
		return nil
	}
	return p.Data[po+off : po+off+n]
}

// extractDNSQuery 返回首个 DNS 查询名（[]byte(string) 会分配，正常）。
// 什么时候是 nil：Ctx/Pkt 为 nil；非 DNS 包（P.DNS == nil）；Questions 为空。
func extractDNSQuery(c *Ctx) []byte {
	if c == nil || c.Pkt == nil || c.Pkt.DNS == nil {
		return nil
	}
	q := c.Pkt.DNS.Questions
	if len(q) == 0 {
		return nil
	}
	return []byte(q[0].Name)
}

// extractTLSSNI 返回 TLS SNI（[]byte(string) 会分配，正常）。
// 什么时候是 nil：Ctx/Pkt 为 nil；非 TLS 包（P.TLS == nil）；SNI 为空串。
func extractTLSSNI(c *Ctx) []byte {
	if c == nil || c.Pkt == nil || c.Pkt.TLS == nil {
		return nil
	}
	if c.Pkt.TLS.SNI == "" {
		return nil
	}
	return []byte(c.Pkt.TLS.SNI)
}

// extractStream 返回该方向**已重组**的流字节（P1）。
// 本步只做「接缝」，不实现重组器：没有重组器时 ctx.Stream 一律为 nil，
// 等价于缓冲区不存在，引擎按既有语义处理。
// 什么时候是 nil：Ctx/Ctx.Pkt 为 nil；c.Stream 为 nil（缓冲区不存在）；
// 方向非法；该方向切片为空（len==0，空数据等同不存在，与既有提取器一致）。
// ★ 直接返回上游给的切片，不复制；生命周期由上层（reassembly）负责。
func extractStream(c *Ctx) []byte {
	if c == nil || c.Pkt == nil || c.Stream == nil {
		return nil
	}
	if c.Stream.Midstream() {
		// ★ C′（窄口径防漏）：重组不可信 ⇒ 本包退化为单包匹配，绝不因为「流残缺」而漏检。
		// 只对「真的出现过落在基准之前的段」的包/流生效，其它中途流照旧用 stream。
		return extractPayload(c)
	}
	var b []byte
	switch c.Pkt.StreamDir {
	case 0:
		b = c.Stream.BytesToServer()
	case 1:
		b = c.Stream.BytesToClient()
	default:
		return nil
	}
	if len(b) == 0 {
		return nil
	}
	return b
}
