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
	Total int // 总条数（用于分页导航；实现应返回真实条数）
}

// CaptureCounter 是 CaptureStore 的**可选扩展**：返回 capture 真实总条数。
//
// ★ 为什么不把 Count 直接并进 CaptureStore：接口一加方法，所有实现者
// （PG、hoststore、若干测试替身）都得同步修改，还会牵动跨进程 RPC 契约。
// 调用方按「能力探测」使用：
//
//	if c, ok := st.Captures().(storage.CaptureCounter); ok {
//	    n, err := c.Count(ctx)
//	}
type CaptureCounter interface {
	Count(ctx context.Context) (int, error)
}

// Pinger 是 Storage 的**可选扩展**：周期性健康探测（数据库连接是否仍可用）。
//
// bootstrap 的存储巡检用它判断"当前可用"的存储是否已经掉线；不并进
// Storage 接口同样是为了不破坏既有实现与测试替身。
type Pinger interface {
	Ping(ctx context.Context) error
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

// Endpoint 连接的一端（IP + 端口）。IP 用字符串形式（IPv4/IPv6 均可）。
type Endpoint struct {
	IP   string
	Port uint16
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

// PacketFlowQuerier 是 PacketStore 的**可选扩展**：支持"按连接（四元组双向）查包"。
//
// ★ 为什么**不**并进 PacketStore：接口一加方法，**所有实现者**都得跟上
// （`store` 的 PG 实现、`common/hoststore` 的插件侧 RPC 适配器，以及若干测试替身），
// 还会牵动**跨进程 RPC 协议**；而当前只有**宿主进程内**的证据导出需要这个能力。
// ⇒ 按「能力探测」的方式扩展：调用方做类型断言，拿不到就降级。
//
// 用法：
//
//	if q, ok := st.Packets().(storage.PacketFlowQuerier); ok {
//	    res, err := q.ListByEndpoints(ctx, ep1, ep2, storage.Page{Limit: 1000})
//	}
type PacketFlowQuerier interface {
	// ListByEndpoints 按「四元组双向」分页查询包元数据：返回 ep1→ep2 与 ep2→ep1
	// 两个方向的包，按 (time, capture_id, no) 升序。这是**跨 capture** 的查询
	// （同一条连接的包可能分布在多个 capture 文件里），返回值带 CaptureID，
	// 调用方据此回原始文件取帧。
	//
	// 为什么用四元组而不是五元组：PacketRecord.Proto 是展示名（"TLSv1.2"/"DNS"…），
	// 与调用方手里的传输层语义连接对不上 ⇒ 用 IP+端口匹配更可靠。
	// 为什么双向：调用方只想表达"这条连接"，不该被迫关心方向。
	ListByEndpoints(ctx context.Context, ep1, ep2 Endpoint, page Page) (*PageResult[PacketRecord], error)
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
