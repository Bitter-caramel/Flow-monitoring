// Package reassembly 包装 gopacket 的 TCP 重组（reassembly）包，
// 负责「流字节存在哪儿、存多少、给谁看」。
//
// 设计依据：docs/已完成/TCP重组.md §2/§6/§7。
// 本步（11-3）只新建模块与测试：不改检测引擎、不改默认粘性缓冲
// （默认粘性缓冲见 11-2，热路径接入见 11-4）。
package reassembly

import "time"

// Options 重组器配置。
type Options struct {
	// MemCap 所有流缓冲总量上限（默认 64<<20）。
	// 超限时按「最久未活动」淘汰流并计数，保证总量不无界增长。
	MemCap int64
	// FlowTimeout 无新包多久回收流（默认 60s）。
	// 本步只做持有与暴露，不做后台定时器（定时回收见后续子任务）。
	FlowTimeout time.Duration
	// MaxStreamBytes 单流单方向上限（默认 1<<20）。
	// 超了停止追加并标记 Truncated（匹配与证据都要如实体现）。
	MaxStreamBytes int
	// Skip 为 true 时完全不重组：
	// 规则集里没有任何 stream 缓冲时用它走零开销路径。
	Skip bool
}

// DefaultOptions 返回默认配置（与 docs/已完成/TCP重组.md §6 的资源红线一致）。
func DefaultOptions() Options {
	return Options{
		MemCap:         64 << 20,         // 64 MB
		FlowTimeout:    60 * time.Second, // 60 s
		MaxStreamBytes: 1 << 20,          // 1 MB / 方向
		Skip:           false,
	}
}

// Direction 流的半连接方向。
//
// 约定与 detect 的 StreamDir 一致：0 = 包从 A 走向 B（较低地址方向），
// 1 = 包从 B 走向 A。extractor 用 StreamDir 选择 BytesToServer/BytesToClient，
// 因此这里必须沿用同一套归一化方向，绝不另外发明一套。
type Direction uint8

const (
	ToServer Direction = 0 // A→B（与 p.StreamDir==0 对应）
	ToClient Direction = 1 // B→A（与 p.StreamDir==1 对应）
)

// StreamStats 单个方向的重组统计。
type StreamStats struct {
	Bytes     int64 // 已交付字节数
	Truncated bool  // 是否因 MaxStreamBytes 截断
	Gaps      int   // 检测到的洞（缺失段）个数
	GapBytes  int64 // 洞覆盖的字节数（能估多少算多少，拿不到就 0）
}
