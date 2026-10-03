// 三类实时统计：协议、端点（IP 对）、端口。
//
// 这些统计随 Feed 增量维护（每个通过 IPv4+TCP/UDP 过滤的有效包各计一次），
// 与流聚合/状态机解耦，仅做轻量累加，供 UI 与检测模块消费。
//
// 统计口径：
//   - 协议统计：按 p.Proto（协议名字符串）累加包数与字节数（CapLen）；
//   - 端点统计：按 IP 对（不区分端口）双向合并，A=低 IP、B=高 IP，
//     复用五元组规范化的 IP 归一逻辑（取 Feed 中已规范化的 key.A/key.B）；
//   - 端口统计：p.SrcPort 与 p.DstPort 各计 1 个包（同一包两端各记一次）。
//
// 快照由 Stats() 返回，均为副本，调用方修改不会影响聚合器内部状态。
package analyzer

import "flow-monitoring/internal/kernel/datamodel"

// ProtoStat 单个协议的统计：包数 + 字节数。
type ProtoStat struct {
	Packets uint64 // 包数
	Bytes   uint64 // 字节数（capLen 累加）
}

// EndpointKey 是端点统计的键：一对 IP，A=低 IP、B=高 IP（不区分端口与协议）。
//
// 字段导出，便于下游遍历/精确查找；同一 IP 对的两个方向都会归并到同一个键。
type EndpointKey struct {
	A uint32 // 低 IP
	B uint32 // 高 IP
}

// EndpointStat 单个 IP 对的统计：包数 + 字节数，双向合并。
type EndpointStat struct {
	A       uint32 // 低 IP
	B       uint32 // 高 IP
	Packets uint64 // 包数（双向合计）
	Bytes   uint64 // 字节数（双向合计，capLen 累加）
}

// Stats 三类统计快照。
//
// Protocols 以协议名为键；Endpoints 以规范化 IP 对为键；Ports 以端口为键。
type Stats struct {
	Protocols map[string]ProtoStat         // 协议名 -> 统计
	Endpoints map[EndpointKey]EndpointStat // IP 对 -> 统计
	Ports     map[uint16]uint64            // 端口 -> 包数（源/目的各计一次）
}

// updateStats 把一个有效包累加到三类统计中。
//
// p 需已通过 Feed 的 IPv4+TCP/UDP 过滤；k 为该包规范化后的五元组
// （k.A=低 IP、k.B=高 IP），端点统计直接复用其 IP 归一结果。
func (a *Analyzer) updateStats(p *datamodel.Packet, k key) {
	if a == nil || p == nil {
		return
	}

	// 协议统计：按协议名字符串累加。
	ps := a.protoStats[p.Proto]
	ps.Packets++
	ps.Bytes += uint64(p.CapLen)
	a.protoStats[p.Proto] = ps

	// 端点统计：IP 对双向合并（k.A/k.B 已是低/高 IP 归一结果）。
	ek := EndpointKey{A: k.A, B: k.B}
	es := a.endpointStats[ek]
	es.A = ek.A
	es.B = ek.B
	es.Packets++
	es.Bytes += uint64(p.CapLen)
	a.endpointStats[ek] = es

	// 端口统计：源、目的端口各计 1 个包。
	a.portStats[p.SrcPort]++
	a.portStats[p.DstPort]++
}

// Stats 返回当前三类统计的快照。
//
// 返回的 map 均为新建副本，调用方修改不会影响聚合器内部状态；
// nil 接收者返回零值 Stats（各 map 为 nil）。
func (a *Analyzer) Stats() Stats {
	if a == nil {
		return Stats{}
	}
	out := Stats{
		Protocols: make(map[string]ProtoStat, len(a.protoStats)),
		Endpoints: make(map[EndpointKey]EndpointStat, len(a.endpointStats)),
		Ports:     make(map[uint16]uint64, len(a.portStats)),
	}
	for name, st := range a.protoStats {
		out.Protocols[name] = st
	}
	for ek, st := range a.endpointStats {
		out.Endpoints[ek] = st
	}
	for port, cnt := range a.portStats {
		out.Ports[port] = cnt
	}
	return out
}
