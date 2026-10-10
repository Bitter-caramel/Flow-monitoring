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

// Ctx 一次检测的输入单元。
// 今天只有「包 + 它所属的流」；将来上 TCP 重组，只是这里多一个字段 ——
// 引擎其余部分不动。
type Ctx struct {
	Pkt  *datamodel.Packet
	Flow *datamodel.Flow
	// P1: Stream *reassembly.Stream
}
