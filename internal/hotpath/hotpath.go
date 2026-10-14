// Package hotpath 把「归流 → 重组 → 检测」这条热路径编排收敛到一处，
// 供 cmd/parse-cli 与端到端/golden 测试共用（避免测试自己抄一份接线）。
package hotpath

import (
	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/modules/detect"
	"flow-monitoring/internal/modules/parse/analyzer"
	"flow-monitoring/internal/modules/reassembly"
	"flow-monitoring/internal/modules/rule"
)

// Hotpath 封装「归流 → 重组 → 检测」这条热路径编排。
//
// 它持有流分析器、检测引擎与（可选的）重组器三个部件，
// 调用方只需逐包调用 Process，即可完成一次完整的检测编排。
type Hotpath struct {
	az    *analyzer.Analyzer
	eng   *detect.Engine
	reasm *reassembly.Reassembler
}

// New 依据规则集构造：引擎来自 rs.Engine()。
//
// ★ 仅当规则集引用了 stream 缓冲（rs.UsesBuffer(rule.BufStream)）时才建重组器，
// 否则 reasm 为 nil —— 这就是 11-4 的"跳过优化"（不用则零开销）。
// rs 为 nil 时 eng 与 reasm 均为 nil，Process 返回 nil（不 panic）。
func New(rs *detect.RuleSet) *Hotpath {
	h := &Hotpath{az: analyzer.New()}
	if rs == nil {
		return h
	}
	h.eng = rs.Engine()
	// ★ 跳过优化：规则集里没有任何条件引用 stream 缓冲时，完全不建重组器
	// （零开销）。用了 stream 才 New，并由调用方 defer Close。
	if rs.UsesBuffer(rule.BufStream) {
		h.reasm = reassembly.New(reassembly.DefaultOptions())
	}
	return h
}

// Analyzer 返回内部的流分析器（对 New 构造的实例永不为 nil），供上层打印聚合结果。
func (h *Hotpath) Analyzer() *analyzer.Analyzer {
	if h == nil {
		return nil
	}
	return h.az
}

// Engine 返回检测引擎；rs 为 nil 时为 nil。
func (h *Hotpath) Engine() *detect.Engine {
	if h == nil {
		return nil
	}
	return h.eng
}

// Reassembles 报告是否建了重组器（供测试与观测；等价于 11-4 的"跳过优化"是否生效）。
func (h *Hotpath) Reassembles() bool {
	if h == nil {
		return false
	}
	return h.reasm != nil
}

// Process 处理一个「已经解码」的包：归流 → 喂重组器 → 匹配，返回本包全部命中。
//
// ★ 顺序红线：必须先把包喂给重组器再做匹配，否则当包看不到自己那段流
// （docs/TCP重组.md §5；这也是 11-4 在 main.go 里写死的那条）。
// h 为 nil / p 为 nil / eng 为 nil 时返回 nil，不 panic。
func (h *Hotpath) Process(p *datamodel.Packet) []detect.Alert {
	if h == nil || p == nil || h.eng == nil {
		return nil
	}
	flow := h.az.FeedFlow(p)
	// ★ 顺序红线：先 Feed 再 Match —— 否则当包看不到自己刚写进重组器的那段流。
	if h.reasm != nil {
		h.reasm.Feed(p)
	}
	return h.eng.Match(&detect.Ctx{Pkt: p, Flow: flow, Stream: viewOf(h.reasm, p)})
}

// Close 释放重组器；幂等；没有重组器时是 no-op。
func (h *Hotpath) Close() {
	if h == nil || h.reasm == nil {
		return
	}
	h.reasm.Close()
}

// viewOf 返回这个包所在流的流视图；没有重组器时返回 nil（= 没有流数据）。
//
// ★ 宁可传 nil 也不要传一个空实现：Ctx.Stream 是接口，nil 与「空的流视图」
// 在引擎里语义一致（都表示缓冲区不存在），但 nil 不引入任何分配，
// 也不会让引擎误以为「有流数据只是恰好为空」。
func viewOf(r *reassembly.Reassembler, p *datamodel.Packet) detect.StreamView {
	if r == nil {
		return nil
	}
	return r.View(p)
}
