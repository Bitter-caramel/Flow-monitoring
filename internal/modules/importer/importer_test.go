package importer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"flow-monitoring/internal/kernel/storage"
	"flow-monitoring/internal/modules/packetstore"
)

// memStorage 内存存储替身（验证 importer 编排）。
type memStorage struct {
	captures map[string]*storage.CaptureRecord
	packets  map[string][]storage.PacketRecord
}

func newMemStorage() *memStorage {
	return &memStorage{captures: map[string]*storage.CaptureRecord{}, packets: map[string][]storage.PacketRecord{}}
}

func (m *memStorage) Captures() storage.CaptureStore { return &memCaptureStore{m} }
func (m *memStorage) Packets() storage.PacketStore   { return &memPacketStore{m} }
func (m *memStorage) Close() error                   { return nil }

type memCaptureStore struct{ m *memStorage }

func (s *memCaptureStore) Create(_ context.Context, rec *storage.CaptureRecord) error {
	s.m.captures[rec.ID] = rec
	return nil
}
func (s *memCaptureStore) Get(_ context.Context, id string) (*storage.CaptureRecord, error) {
	if r, ok := s.m.captures[id]; ok {
		return r, nil
	}
	return nil, storage.ErrNotFound
}
func (s *memCaptureStore) List(_ context.Context, _ storage.Page) (*storage.PageResult[storage.CaptureRecord], error) {
	return nil, nil
}
func (s *memCaptureStore) Delete(_ context.Context, id string) error {
	delete(s.m.captures, id)
	return nil
}

type memPacketStore struct{ m *memStorage }

func (s *memPacketStore) SaveBatch(_ context.Context, id string, pkts []storage.PacketRecord) error {
	s.m.packets[id] = append(s.m.packets[id], pkts...)
	return nil
}
func (s *memPacketStore) ListByCapture(_ context.Context, id string, _ storage.Page) (*storage.PageResult[storage.PacketRecord], error) {
	return &storage.PageResult[storage.PacketRecord]{Items: s.m.packets[id], Total: len(s.m.packets[id])}, nil
}
func (s *memPacketStore) Count(_ context.Context, id string) (int, error) {
	return len(s.m.packets[id]), nil
}
func (s *memPacketStore) DeleteByCapture(_ context.Context, id string) error {
	delete(s.m.packets, id)
	return nil
}

// testPcapng 读取 testdata/test.pcapng。
func testPcapng(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "testdata", "test.pcapng")
	abs, _ := filepath.Abs(path)
	data, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	return data
}

// TestImport 导入真实 pcapng：解析 → 解码 → 入库。
func TestImport(t *testing.T) {
	db := newMemStorage()
	ps, err := packetstore.New(t.TempDir(), db)
	if err != nil {
		t.Fatalf("packetstore.New: %v", err)
	}
	imp := New(ps)

	data := testPcapng(t)
	rec, err := imp.Import(context.Background(), "", "test-import", data)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	// Capture 元数据
	if rec.ID == "" {
		t.Error("ID should not be empty")
	}
	if rec.PacketCount != 18 {
		t.Errorf("PacketCount = %d, want 18", rec.PacketCount)
	}
	if rec.SHA256 == "" {
		t.Error("SHA256 should not be empty")
	}

	// 包索引入库
	if len(db.packets[rec.ID]) != 18 {
		t.Errorf("packets indexed = %d, want 18", len(db.packets[rec.ID]))
	}

	// 检查第一个包的元数据合理性
	first := db.packets[rec.ID][0]
	if first.No != 1 {
		t.Errorf("first.No = %d, want 1", first.No)
	}
	if first.Proto == "" {
		t.Error("first packet Proto should not be empty")
	}

	// 文件已写入
	if _, err := os.Stat(filepath.Join(ps.Dir(), rec.FilePath)); err != nil {
		t.Errorf("raw file not found: %v", err)
	}
}

// TestImport_Idempotent 相同文件生成相同 ID（幂等）。
func TestImport_Idempotent(t *testing.T) {
	data := testPcapng(t)
	id1 := genID(data)
	id2 := genID(data)
	if id1 != id2 {
		t.Errorf("genID not deterministic: %s != %s", id1, id2)
	}
}

// TestImport_Empty 空文件报错。
func TestImport_Empty(t *testing.T) {
	imp := New(&packetstore.Store{})
	if _, err := imp.Import(context.Background(), "", "empty", nil); err == nil {
		t.Error("empty file should error")
	}
}
