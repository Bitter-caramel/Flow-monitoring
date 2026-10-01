package datamodel

import "time"

// Flow 五元组粒度的流对象。
//
// 对应 v0.3 架构第 9.2 节 Flow 结构（"流级轻量"层级）：
//   - 由解析内核产出，数量巨大、生命周期短
//   - 仅做统计不过度留痕，评分与处置都在 Subject 上做
//
// 字段 A/B 为规范化五元组：A=低地址方向，B=高地址方向，
// 对应 PacketLens skey() (index.html:4627) 的"流键规范化"逻辑。
// 同一对话的两个方向归并到同一 Flow。
type Flow struct {
	ID        uint64
	Kind      string // "tcp" / "udp"
	A         uint32 // 规范化源 IPv4 整数（低地址）
	APort     uint16 // A 端口
	B         uint32 // 规范化目的 IPv4 整数（高地址）
	BPort     uint16 // B 端口
	Protocol  uint8  // IP 协议号（6/17）
	PacketCnt uint64
	ByteCnt   uint64
	FirstSeen time.Time
	LastSeen  time.Time

	// 流健康度（TCP 流分析产出，UDP 仅统计）
	State           FlowState // ESTABLISHED/HALF_CLOSE/CLOSED/RESET/UNKNOWN
	RTT             time.Duration
	Retransmissions int
	ZeroWindows     int
	DupACKs         int
	Gaps            int           // 流缺口数
	HSRTT           time.Duration // 握手 RTT（SYN-SYN/ACK-ACK 算）
	SynNo           int           // SYN 包号
	SynAckNo        int           // SYN-ACK 包号
	RstNo           int           // RST 包号
	Swap            bool          // 流是否被规范化方向调换过

	// 应用层识别
	AppProto string   // 识别出的应用协议（http/tls/telnet/ftp/...）
	AppMeta  *AppMeta // 应用层摘要（按需分配）

	// 双向统计（[0]=A→B, [1]=B→A）
	Dirs [2]FlowDir
}

// FlowDir 单方向流量统计。
type FlowDir struct {
	Packets   uint64
	Bytes     uint64
	DataBytes uint64
	Segments  []SegmentDesc // TCP 流分段（流重组用）
}

// SegmentDesc TCP 流分段描述符。
// 对应 PacketLens packSegments 输出的 {abs, off, len, idx, time}。
type SegmentDesc struct {
	AbsTime time.Time
	Off     int // 在流重组缓冲中的偏移
	Len     int
	PktIdx  int // 包在 packets 切片中的下标
	Time    time.Time
}

// FlowState TCP 流状态。
type FlowState int

const (
	FlowUnknown     FlowState = iota // 未识别
	FlowEstablished                  // ESTABLISHED（完成握手）
	FlowHalfClose                    // 半关闭（一方 FIN）
	FlowClosed                       // 完全关闭
	FlowReset                        // RST 异常终止
)

// AppMeta 应用层语义摘要（按需挂到 Flow 上）。
type AppMeta struct {
	// DNS/HTTP/TLS 等具体摘要；哪个填充由 AppProto 决定
	HTTPMethod string
	HTTPURI    string
	HTTPStatus int
	TLSSNI     string
	TLSCertCN  string
	DNSQuery   string
	DNSRCode   uint8
	// ... 按需扩充
}

// Session 会话对象（高于 Flow 的应用层语义聚合）。
// 对应实施方案 2.0 第 5.2 节 Session 定义。
//
// 一个 Session 可包含多个 Flow：
//   - HTTP 事务：单 TCP 流 + 请求-响应一对
//   - DNS 事务：单 UDP 流（或 TCP）+ 一对 query/response
//   - TLS 会话：单 TCP 流 + 完整握手到加密数据
type Session struct {
	ID         string
	Kind       string // "http"/"dns"/"tls"/"tcp"/"udp"
	FlowIDs    []uint64
	StartTime  time.Time
	EndTime    time.Time
	IsComplete bool   // 是否完整（请求+响应都有）
	PayloadRef string // 应用层载荷在存储中的引用
}
