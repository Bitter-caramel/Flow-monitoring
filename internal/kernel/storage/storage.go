package storage

import (
	"context"
	"time"
)

// CaptureRecord 抓包文件元数据（对应 captures 表）。
//
// 只存元数据，不存包字节；原始文件路径由 FilePath 引用。
// 对应 datamodel.CaptureSummary 的持久化形态。
type CaptureRecord struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Format      string    `json:"format"`       // pcapng/pcap/...
	LinkType    int       `json:"link_type"`    // LINKTYPE_*
	PacketCount int       `json:"packet_count"`
	ByteSize    int64     `json:"byte_size"`    // 原始文件字节数
	FilePath    string    `json:"file_path"`    // 原始 pcap 文件路径
	SHA256      string    `json:"sha256"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	ImportedAt  time.Time `json:"imported_at"`
}

// PacketRecord 数据包元数据（对应 packets 表）。
//
// 只存 L2/L3/L4 关键元数据与 INFO 摘要，不含原始字节。
// 原始字节按 CaptureRecord.FilePath + 包内偏移在文件层读取。
type PacketRecord struct {
	CaptureID string    `json:"capture_id"`
	No        int       `json:"no"`         // 包序号（从 1 开始）
	Time      time.Time `json:"time"`       // 绝对时间
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Proto     string    `json:"proto"`      // 协议名（TCP/UDP/DNS/HTTP/TLS...）
	Info      string    `json:"info"`       // Wireshark 风格 INFO
	CapLen    int       `json:"cap_len"`    // 抓取长度
	OrigLen   int       `json:"orig_len"`   // 原始长度
}

// Page 分页参数。
type Page struct {
	Offset int
	Limit  int
}

// PageResult 分页结果。
type PageResult[T any] struct {
	Items []T
	Total int // 总条数（用于分页导航；-1 表示未统计）
}

// CaptureStore 抓包元数据存取接口。
type CaptureStore interface {
	// Create 保存一个抓包元数据记录。
	Create(ctx context.Context, rec *CaptureRecord) error

	// Get 按 ID 查询。
	Get(ctx context.Context, id string) (*CaptureRecord, error)

	// List 分页列出（按 ImportedAt 倒序）。
	List(ctx context.Context, page Page) (*PageResult[CaptureRecord], error)

	// Delete 删除（软删除；实现层负责二次确认与审计）。
	Delete(ctx context.Context, id string) error
}

// PacketStore 数据包元数据存取接口。
type PacketStore interface {
	// SaveBatch 批量写入包元数据（大文件分块调用）。
	SaveBatch(ctx context.Context, captureID string, packets []PacketRecord) error

	// ListByCapture 按 captureID 分页查询包元数据（按 No 升序）。
	ListByCapture(ctx context.Context, captureID string, page Page) (*PageResult[PacketRecord], error)

	// Count 统计某 capture 的包总数。
	Count(ctx context.Context, captureID string) (int, error)

	// DeleteByCapture 删除某 capture 的全部包元数据。
	DeleteByCapture(ctx context.Context, captureID string) error
}

// Storage 存储聚合接口。
//
// 由具体实现（PostgreSQL / 内存替身）组合各个 Store。
// bootstrap 或业务模块依赖此接口，不依赖具体实现。
type Storage interface {
	Captures() CaptureStore
	Packets() PacketStore
	// Close 关闭底层连接。
	Close() error
}
