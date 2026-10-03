// Package analyzer 实现按规范化五元组聚合的流聚合器。
//
// 设计依据：
//   - datamodel.Flow/FlowDir 的"流级轻量"模型（v0.3 架构第 9.2 节）
//   - PacketLens skey() 的"流键规范化"逻辑：A=低地址方向、B=高地址方向，
//     同一对话的两个方向归并到同一条 Flow
//
// 使用方式：
//
//	a := analyzer.New()
//	for _, p := range packets {
//	    a.Feed(p) // 解码后的包，Feed 会回写 p.StreamID / p.StreamDir
//	}
//	flows := a.Flows()
//
// 本包做流级统计（包/字节/首末时间/双向计数）与 TCP 状态机（见 tcp.go），
// 不做 L7 语义或存储落盘，保持"流级轻量"的定位。
package analyzer

import (
	"flow-monitoring/internal/kernel/datamodel"
)

// key 是规范化五元组：A=低地址方向、B=高地址方向。
// 使用定长值类型作为 map key，避免为每个包分配字符串。
type key struct {
	A     uint32
	APort uint16
	B     uint32
	BPort uint16
	Proto uint8
}

// Analyzer 流聚合器。
//
// 持有 flow 映射表（key 为规范化五元组）与自增 flow ID。
// 零值不可用，请使用 New 构造。
type Analyzer struct {
	flows  map[key]*datamodel.Flow // 五元组 -> Flow
	order  []*datamodel.Flow       // 按创建顺序保存，保证 Flows() 输出稳定
	nextID uint64                  // 自增 flow ID（从 1 开始）

	// 三类统计（见 stats.go）：随 Feed 增量维护。
	protoStats    map[string]ProtoStat         // 协议名 -> 统计
	endpointStats map[EndpointKey]EndpointStat // 规范化 IP 对 -> 统计
	portStats     map[uint16]uint64            // 端口 -> 包数
}

// New 构造一个空的流聚合器。
func New() *Analyzer {
	return &Analyzer{
		flows:         make(map[key]*datamodel.Flow),
		protoStats:    make(map[string]ProtoStat),
		endpointStats: make(map[EndpointKey]EndpointStat),
		portStats:     make(map[uint16]uint64),
	}
}

// Feed 把一个解码后的包喂给聚合器。
//
// 仅处理 IPv4（IPVersion==4）且为 TCP（IPProto==6）或 UDP（IPProto==17）
// 的包，其它包直接返回。成功归并后回写 p.StreamID 与 p.StreamDir。
func (a *Analyzer) Feed(p *datamodel.Packet) {
	if a == nil || p == nil {
		return
	}
	// 只处理 IPv4 的 TCP/UDP。
	if p.IPVersion != 4 {
		return
	}
	if p.IPProto != 6 && p.IPProto != 17 {
		return
	}

	// 五元组规范化：A=低地址方向，B=高地址方向。
	var (
		k    key
		dir  int
		swap bool
	)
	switch {
	case p.SrcIPNum < p.DstIPNum:
		// 源地址较低：源即 A 方向。
		k = key{p.SrcIPNum, p.SrcPort, p.DstIPNum, p.DstPort, p.IPProto}
		dir = 0
	case p.SrcIPNum > p.DstIPNum:
		// 源地址较高：目的才是 A 方向，包方向为 B→A。
		k = key{p.DstIPNum, p.DstPort, p.SrcIPNum, p.SrcPort, p.IPProto}
		dir = 1
		swap = true
	default:
		// IP 相等（理论上的同主机通信）：退化到端口比。
		if p.SrcPort <= p.DstPort {
			k = key{p.SrcIPNum, p.SrcPort, p.DstIPNum, p.DstPort, p.IPProto}
			dir = 0
		} else {
			k = key{p.DstIPNum, p.DstPort, p.SrcIPNum, p.SrcPort, p.IPProto}
			dir = 1
			swap = true
		}
	}

	f := a.flows[k]
	if f == nil {
		// 新建流：分配自增 ID 并填充规范化五元组与类型。
		a.nextID++
		f = &datamodel.Flow{
			ID:       a.nextID,
			A:        k.A,
			APort:    k.APort,
			B:        k.B,
			BPort:    k.BPort,
			Protocol: k.Proto,
			Swap:     swap,
			State:    datamodel.FlowUnknown,
		}
		if k.Proto == 6 {
			f.Kind = "tcp"
		} else {
			f.Kind = "udp"
		}
		a.flows[k] = f
		a.order = append(a.order, f)
	}

	// 汇总统计。
	f.PacketCnt++
	f.ByteCnt += uint64(p.CapLen)
	if f.FirstSeen.IsZero() || p.Time.Before(f.FirstSeen) {
		f.FirstSeen = p.Time
	}
	if f.LastSeen.IsZero() || p.Time.After(f.LastSeen) {
		f.LastSeen = p.Time
	}

	// 双向统计（[0]=A→B, [1]=B→A）。
	f.Dirs[dir].Packets++
	f.Dirs[dir].Bytes += uint64(p.CapLen)
	f.Dirs[dir].DataBytes += uint64(p.PayloadLen)

	// TCP 状态机：仅对 TCP 包推进状态，UDP 包跳过。
	if k.Proto == 6 {
		advanceTCPState(f, p, dir)
	}

	// 三类统计：协议/端点/端口（放在流聚合与状态机之后增量维护）。
	a.updateStats(p, k)

	// 回写流归属，供下游（存储/查询/展示）消费。
	p.StreamID = int(f.ID)
	p.StreamDir = uint8(dir)
}

// Flows 返回当前所有流。
//
// 返回的切片按流创建（ID 递增）顺序排列，便于验证与下游消费；
// 切片为新建副本，调用方修改切片本身不会影响聚合器内部状态。
func (a *Analyzer) Flows() []*datamodel.Flow {
	if a == nil {
		return nil
	}
	out := make([]*datamodel.Flow, len(a.order))
	copy(out, a.order)
	return out
}

// Flow 按规范化五元组查询单条流，未命中返回 nil。
// 供需要 O(1) 精确查找的下游使用。
func (a *Analyzer) Flow(aIP uint32, aPort uint16, bIP uint32, bPort uint16, proto uint8) *datamodel.Flow {
	if a == nil {
		return nil
	}
	return a.flows[key{aIP, aPort, bIP, bPort, proto}]
}

// Len 返回当前已聚合的流数量。
func (a *Analyzer) Len() int {
	if a == nil {
		return 0
	}
	return len(a.flows)
}
