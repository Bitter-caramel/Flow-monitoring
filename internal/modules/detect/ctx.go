// Package detect 是检测引擎：把「规则」与「流量」接起来。
//
// rule 包把文本规则编译成与数据源无关的 CompiledRule；
// 本包再把 CompiledRule 二次编译（Compile）成可直接执行的 Program，
// 完成「取字节」（Extractor）与「绑定」（Cond.Extract 函数指针）。
//
// 本步只做提取与绑定，不做匹配执行（匹配逻辑见 9-3）。
//
// 约束：Ctx 是只读的，检测绝不修改 Pkt / Flow。
package detect

import "flow-monitoring/internal/kernel/datamodel"

// StreamView 由上层（将来的 reassembly 模块）实现，detect 只认这个接口，不认识 gopacket。
// 两个方法返回该方向**已重组**的字节；数据不存在时返回 nil（= 缓冲区不存在，与 Extractor 约定一致）。
type StreamView interface {
	BytesToServer() []byte
	BytesToClient() []byte
	// Midstream 报告「重组视图不可信」：这条流出现过落在重组基准之前的段
	// （中途抓包 + 乱序 ⇒ 这些段会永远搁浅，见 docs/已完成/TCP重组.md §7.3）。
	// 它由 reassembly 侧实现；没有流（空视图）时为 false。
	Midstream() bool
}

// Ctx 一次检测的输入单元。
// 今天只有「包 + 它所属的流」；将来上 TCP 重组，只是这里多一个字段 ——
// 引擎其余部分不动。
type Ctx struct {
	Pkt  *datamodel.Packet
	Flow *datamodel.Flow
	// Stream 是 TCP 重组后的流视图（P1）；nil = 没有流数据（缓冲区不存在）。
	Stream StreamView
}
