package packetstore

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/storage"
)

// memStorage 内存存储替身（验证编排，不依赖 PG）。
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
func (s *memPacketStore) Count(_ context.Context, id string) (int, error) { return len(s.m.packets[id]), nil }
func (s *memPacketStore) DeleteByCapture(_ context.Context, id string) error {
	delete(s.m.packets, id)
	return nil
}

// TestSaveCapture 保存 capture：文件 + 元数据 + 包索引。
func TestSaveCapture(t *testing.T) {
	dir := t.TempDir()
	db := newMemStorage()
	s, err := New(dir, db)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	raw := []byte{0x0a, 0x0d, 0x0d, 0x0a, 1, 2, 3}
	pkts := []storage.PacketRecord{
		{No: 1, Proto: "TCP", Time: time.Now()},
		{No: 2, Proto: "UDP", Time: time.Now()},
	}

	rec, err := s.SaveCapture(context.Background(), "cap-1", "test", raw, pkts)
	if err != nil {
		t.Fatalf("SaveCapture: %v", err)
	}

	// 元数据正确
	if rec.ID != "cap-1" || rec.PacketCount != 2 {
		t.Errorf("rec = %+v, want id=cap-1 count=2", rec)
	}
	if rec.SHA256 == "" {
		t.Error("SHA256 should not be empty")
	}
	if rec.FilePath == "" {
		t.Error("FilePath should not be empty")
	}

	// 文件已写入
	fullPath := filepath.Join(dir, rec.FilePath)
	if _, err := os.Stat(fullPath); err != nil {
		t.Errorf("file not found: %v", err)
	}

	// 索引已写入
	if len(db.packets["cap-1"]) != 2 {
		t.Errorf("packets indexed = %d, want 2", len(db.packets["cap-1"]))
	}
	if db.captures["cap-1"] == nil {
		t.Error("capture should be indexed")
	}

	// 读取原始字节一致
	got, err := s.ReadRaw(rec.FilePath)
	if err != nil {
		t.Fatalf("ReadRaw: %v", err)
	}
	if string(got) != string(raw) {
		t.Error("ReadRaw returned wrong bytes")
	}
}

// TestReadRaw_PathTraversal 目录穿越防护。
func TestReadRaw_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir, nil)

	// 尝试读取目录外的文件
	outside := filepath.Join(t.TempDir(), "secret.txt")
	_ = os.WriteFile(outside, []byte("secret"), 0o644)

	if _, err := s.ReadRaw(outside); err == nil {
		t.Error("path traversal should be rejected")
	}
}

// TestPathWithin 路径包含判断。
func TestPathWithin(t *testing.T) {
	cases := []struct {
		parent, child string
		want          bool
	}{
		{"/data", "/data/file.bin", true},
		{"/data", "/etc/passwd", false},
		{"/data", "/data/../secret", false},
	}
	for _, tc := range cases {
		if got := pathWithin(tc.parent, tc.child); got != tc.want {
			t.Errorf("pathWithin(%q,%q) = %v, want %v", tc.parent, tc.child, got, tc.want)
		}
	}
}
