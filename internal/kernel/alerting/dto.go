// Package alerting 是宿主机侧的告警视图：它只订阅 eventbus 上的
// "detect.feature" 事件并缓存到环形缓冲，通过 /api/alerts 对外查询。
//
// ★ 它不加载规则、不跑热路径、不 import 任何业务模块（detect/rule/hotpath）：
//
//	跨进程来的是字节，宿主用 json.Unmarshal 解成自己的 DTO 即可，
//	这样内核才能保持「不 import 业务模块」的纯净性（任务 15-2b）。
package alerting

// Alert 宿主侧的告警视图。
//
// ★ 字段名与 capture 进程发布的 JSON 一一对应，但不引用 detect 业务模块，
//
//	这样内核才能保持"不 import 业务模块"。
type Alert struct {
	ID       uint64 `json:"id"` // 宿主分配（单调递增）
	RuleID   string `json:"rule_id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Weight   int    `json:"weight"`
	Time     string `json:"time"` // RFC3339 原文透传
	SrcIP    string `json:"src_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstIP    string `json:"dst_ip"`
	DstPort  uint16 `json:"dst_port"`
	Proto    string `json:"proto"`
	StreamID int    `json:"stream_id"`
	Buffer   string `json:"buffer"`
	Offset   int    `json:"offset"`
	Snippet  string `json:"snippet"`
}
