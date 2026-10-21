package query

import (
	"context"

	"flow-monitoring/internal/kernel/storage"
)

// Service 查询服务。
type Service struct {
	db storage.Storage

	// DataDir 是原始抓包文件目录（默认 "data"）。
	//
	// 由宿主 ConfigSnapshot.DataDir 注入；测试可通过临时目录注入。
	// 保留导出字段是为了调用方/测试能直接设置，同时 SetDataDir 也提供方法入口。
	DataDir string

	// dataDir 是 DataDir 的兼容别名（包内测试可直接注入，不依赖导出字段）。
	dataDir string
}

// New 创建查询服务。
//
// 兼容两种用法：
//
//	New(db)            // DataDir 使用默认 "data"
//	New(db, tmpDataDir) // 显式注入抓包文件目录
func New(db storage.Storage, dataDir ...string) *Service {
	s := &Service{db: db}
	if len(dataDir) > 0 {
		s.dataDir = dataDir[0]
	}
	return s
}

// NewWithDataDir 显式指定抓包文件目录创建查询服务。
func NewWithDataDir(db storage.Storage, dataDir string) *Service {
	return New(db, dataDir)
}

// SetDataDir 注入抓包文件目录（空串表示回退默认 "data"）。
func (s *Service) SetDataDir(dir string) {
	s.dataDir = dir
}

// getDataDir 返回抓包文件目录（导出字段优先，其次包内别名，最后默认 data）。
func (s *Service) getDataDir() string {
	if s.DataDir != "" {
		return s.DataDir
	}
	if s.dataDir != "" {
		return s.dataDir
	}
	return "data"
}

// ListCaptures 分页列出 capture。
func (s *Service) ListCaptures(ctx context.Context, page storage.Page) (*storage.PageResult[storage.CaptureRecord], error) {
	if page.Limit <= 0 {
		page.Limit = 50
	}
	return s.db.Captures().List(ctx, page)
}

// GetCapture 查询单个 capture。
func (s *Service) GetCapture(ctx context.Context, id string) (*storage.CaptureRecord, error) {
	return s.db.Captures().Get(ctx, id)
}

// ListPackets 分页列出某 capture 的包。
func (s *Service) ListPackets(ctx context.Context, captureID string, page storage.Page) (*storage.PageResult[storage.PacketRecord], error) {
	if page.Limit <= 0 {
		page.Limit = 100
	}
	if page.Limit > 1000 {
		page.Limit = 1000 // 单次上限，防止一次拉取过多
	}
	return s.db.Packets().ListByCapture(ctx, captureID, page)
}

// CountPackets 统计某 capture 的包数。
func (s *Service) CountPackets(ctx context.Context, captureID string) (int, error) {
	return s.db.Packets().Count(ctx, captureID)
}
