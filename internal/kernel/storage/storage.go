package storage

import (
	"context"

	"flow-monitoring/pkg/plugin"
)

// 跨进程共享的数据记录类型（别名自 pkg/plugin，保证宿主与模块进程 gob 类型一致）。
type (
	CaptureRecord = plugin.CaptureRecord
	PacketRecord  = plugin.PacketRecord
	Page          = plugin.Page
)

// PageResult 分页结果（进程内泛型；跨进程用 pkg/plugin.CapturePage/PacketPage）。
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
