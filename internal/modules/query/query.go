package query

import (
	"context"

	"flow-monitoring/internal/kernel/storage"
)

// Service 查询服务。
type Service struct {
	db storage.Storage
}

// New 创建查询服务。
func New(db storage.Storage) *Service {
	return &Service{db: db}
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
