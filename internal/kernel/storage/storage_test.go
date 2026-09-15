package storage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// memStorage 内存实现（测试替身，验证接口设计）。
type memStorage struct {
	mu       sync.Mutex
	captures map[string]*CaptureRecord
	packets  map[string][]PacketRecord // captureID -> 按 No 排序
	closed   bool
}

func newMemStorage() *memStorage {
	return &memStorage{
		captures: make(map[string]*CaptureRecord),
		packets:  make(map[string][]PacketRecord),
	}
}

func (m *memStorage) Captures() CaptureStore { return &memCaptureStore{m} }
func (m *memStorage) Packets() PacketStore   { return &memPacketStore{m} }
func (m *memStorage) Close() error           { m.closed = true; return nil }

type memCaptureStore struct{ m *memStorage }

func (s *memCaptureStore) Create(_ context.Context, rec *CaptureRecord) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	if _, ok := s.m.captures[rec.ID]; ok {
		return ErrConflict
	}
	cp := *rec
	s.m.captures[rec.ID] = &cp
	return nil
}

func (s *memCaptureStore) Get(_ context.Context, id string) (*CaptureRecord, error) {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	rec, ok := s.m.captures[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *rec
	return &cp, nil
}

func (s *memCaptureStore) List(_ context.Context, page Page) (*PageResult[CaptureRecord], error) {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	var all []CaptureRecord
	for _, r := range s.m.captures {
		all = append(all, *r)
	}
	total := len(all)
	// 简单切片分页（内存实现不排序，仅验证接口）
	start := page.Offset
	if start > total {
		start = total
	}
	end := start + page.Limit
	if end > total {
		end = total
	}
	return &PageResult[CaptureRecord]{Items: all[start:end], Total: total}, nil
}

func (s *memCaptureStore) Delete(_ context.Context, id string) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	if _, ok := s.m.captures[id]; !ok {
		return ErrNotFound
	}
	delete(s.m.captures, id)
	return nil
}

type memPacketStore struct{ m *memStorage }

func (s *memPacketStore) SaveBatch(_ context.Context, captureID string, packets []PacketRecord) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	s.m.packets[captureID] = append(s.m.packets[captureID], packets...)
	return nil
}

func (s *memPacketStore) ListByCapture(_ context.Context, captureID string, page Page) (*PageResult[PacketRecord], error) {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	all := s.m.packets[captureID]
	total := len(all)
	start := page.Offset
	if start > total {
		start = total
	}
	end := start + page.Limit
	if end > total {
		end = total
	}
	items := append([]PacketRecord(nil), all[start:end]...)
	return &PageResult[PacketRecord]{Items: items, Total: total}, nil
}

func (s *memPacketStore) Count(_ context.Context, captureID string) (int, error) {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	return len(s.m.packets[captureID]), nil
}

func (s *memPacketStore) DeleteByCapture(_ context.Context, captureID string) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	delete(s.m.packets, captureID)
	return nil
}

// TestCaptureStore_CRUD Capture 接口的增删查。
func TestCaptureStore_CRUD(t *testing.T) {
	s := newMemStorage()
	ctx := context.Background()
	rec := &CaptureRecord{
		ID: "cap-1", Name: "test", Format: "pcapng",
		LinkType: 1, PacketCount: 10, ImportedAt: time.Now(),
	}
	if err := s.Captures().Create(ctx, rec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// 重复创建 → 冲突
	if err := s.Captures().Create(ctx, rec); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate Create: want ErrConflict, got %v", err)
	}
	// 查询
	got, err := s.Captures().Get(ctx, "cap-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "test" {
		t.Errorf("Name = %q, want test", got.Name)
	}
	// 未找到
	if _, err := s.Captures().Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get missing: want ErrNotFound, got %v", err)
	}
	// 删除
	if err := s.Captures().Delete(ctx, "cap-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Captures().Get(ctx, "cap-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: want ErrNotFound, got %v", err)
	}
}

// TestPacketStore_BatchAndPage Packet 批量写 + 分页读 + 计数。
func TestPacketStore_BatchAndPage(t *testing.T) {
	s := newMemStorage()
	ctx := context.Background()

	var pkts []PacketRecord
	for i := 0; i < 10; i++ {
		pkts = append(pkts, PacketRecord{CaptureID: "cap-1", No: i + 1, Proto: "TCP"})
	}
	if err := s.Packets().SaveBatch(ctx, "cap-1", pkts); err != nil {
		t.Fatalf("SaveBatch: %v", err)
	}

	count, _ := s.Packets().Count(ctx, "cap-1")
	if count != 10 {
		t.Errorf("Count = %d, want 10", count)
	}

	// 分页取 3 条
	res, err := s.Packets().ListByCapture(ctx, "cap-1", Page{Offset: 0, Limit: 3})
	if err != nil {
		t.Fatalf("ListByCapture: %v", err)
	}
	if len(res.Items) != 3 {
		t.Errorf("Items len = %d, want 3", len(res.Items))
	}
	if res.Total != 10 {
		t.Errorf("Total = %d, want 10", res.Total)
	}
	if res.Items[0].No != 1 {
		t.Errorf("first No = %d, want 1", res.Items[0].No)
	}
}

// TestStorage_Close 关闭接口。
func TestStorage_Close(t *testing.T) {
	s := newMemStorage()
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if !s.closed {
		t.Error("closed should be true")
	}
}
