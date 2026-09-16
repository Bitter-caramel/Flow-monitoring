package plugin

import "time"

// CaptureRecord 抓包文件元数据（跨进程存储契约的一部分）。
//
// 只存元数据，不存包字节；原始文件路径由 FilePath 引用。
// 与 internal/kernel/datamodel.CaptureSummary 对应的是持久化形态。
type CaptureRecord struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Format      string    `json:"format"`     // pcapng/pcap/...
	LinkType    int       `json:"link_type"`  // LINKTYPE_*
	PacketCount int       `json:"packet_count"`
	ByteSize    int64     `json:"byte_size"`  // 原始文件字节数
	FilePath    string    `json:"file_path"`  // 原始 pcap 文件路径
	SHA256      string    `json:"sha256"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	ImportedAt  time.Time `json:"imported_at"`
}

// PacketRecord 数据包元数据（跨进程存储契约的一部分）。
//
// 只存 L2/L3/L4 关键元数据与 INFO 摘要，不含原始字节。
type PacketRecord struct {
	CaptureID string    `json:"capture_id"`
	No        int       `json:"no"`        // 包序号（从 1 开始）
	Time      time.Time `json:"time"`      // 绝对时间
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Proto     string    `json:"proto"`     // 协议名（TCP/UDP/DNS/HTTP/TLS...）
	Info      string    `json:"info"`      // Wireshark 风格 INFO
	CapLen    int       `json:"cap_len"`   // 抓取长度
	OrigLen   int       `json:"orig_len"`  // 原始长度
}

// Page 分页参数。
type Page struct {
	Offset int
	Limit  int
}

// CapturePage 抓包元数据分页结果。
type CapturePage struct {
	Items []CaptureRecord
	Total int // 总条数（-1 表示未统计）
}

// PacketPage 数据包元数据分页结果。
type PacketPage struct {
	Items []PacketRecord
	Total int // 总条数（-1 表示未统计）
}

// EventRecord 事件总线上的跨进程事件（gob 安全）。
//
// 对应实施方案 2.0 第 5.3 节事件主题约定；Data 为 JSON 编码的载荷，
// Seq 为每个主题内单调递增的序号（模块用 since 游标做增量拉取）。
type EventRecord struct {
	Topic   string
	Seq     uint64
	Data    []byte
	TraceID string
	Time    time.Time
}

// ConfigSnapshot 宿主下发给模块进程的配置快照。
//
// 为避免把整个 config 结构体耦合进契约，只下发模块通用字段 + 原始 JSON；
// 模块按需从 Raw 解析自己的配置段。
type ConfigSnapshot struct {
	DataDir  string // 原始抓包文件目录
	HTTPAddr string // 宿主对外 HTTP 地址
	Debug    bool   // 调试模式
	Raw      string // 完整配置 JSON，模块自行解析私有段
}
