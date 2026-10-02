package query

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/storage"
)

// memStorage 内存存储替身。
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
func (s *memCaptureStore) List(_ context.Context, page storage.Page) (*storage.PageResult[storage.CaptureRecord], error) {
	var items []storage.CaptureRecord
	for _, r := range s.m.captures {
		items = append(items, *r)
	}
	start := page.Offset
	if start > len(items) {
		start = len(items)
	}
	end := start + page.Limit
	if end > len(items) {
		end = len(items)
	}
	return &storage.PageResult[storage.CaptureRecord]{Items: items[start:end], Total: len(items)}, nil
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
func (s *memPacketStore) ListByCapture(_ context.Context, id string, page storage.Page) (*storage.PageResult[storage.PacketRecord], error) {
	all := s.m.packets[id]
	start := page.Offset
	if start > len(all) {
		start = len(all)
	}
	end := start + page.Limit
	if end > len(all) {
		end = len(all)
	}
	return &storage.PageResult[storage.PacketRecord]{Items: all[start:end], Total: len(all)}, nil
}
func (s *memPacketStore) Count(_ context.Context, id string) (int, error) {
	return len(s.m.packets[id]), nil
}
func (s *memPacketStore) DeleteByCapture(_ context.Context, id string) error {
	delete(s.m.packets, id)
	return nil
}

// TestHandler_ListCaptures GET /api/v1/captures
func TestHandler_ListCaptures(t *testing.T) {
	db := newMemStorage()
	db.captures["cap-1"] = &storage.CaptureRecord{ID: "cap-1", Name: "a", ImportedAt: time.Now()}
	db.captures["cap-2"] = &storage.CaptureRecord{ID: "cap-2", Name: "b", ImportedAt: time.Now()}

	s := New(db)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/captures", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp pageResponse[storage.CaptureRecord]
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Total != 2 {
		t.Errorf("Total = %d, want 2", resp.Total)
	}
}

// TestHandler_GetCapture GET /api/v1/captures/{id}
func TestHandler_GetCapture(t *testing.T) {
	db := newMemStorage()
	db.captures["cap-1"] = &storage.CaptureRecord{ID: "cap-1", Name: "test"}

	s := New(db)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/captures/cap-1", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got storage.CaptureRecord
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Name != "test" {
		t.Errorf("Name = %q, want test", got.Name)
	}

	// 未找到 → 404
	req404 := httptest.NewRequest(http.MethodGet, "/api/v1/captures/missing", nil)
	rec404 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec404, req404)
	if rec404.Code != http.StatusNotFound {
		t.Errorf("404 status = %d, want 404", rec404.Code)
	}
}

// TestHandler_ListPackets GET /api/v1/captures/{id}/packets
func TestHandler_ListPackets(t *testing.T) {
	db := newMemStorage()
	for i := 0; i < 10; i++ {
		db.packets["cap-1"] = append(db.packets["cap-1"], storage.PacketRecord{No: i + 1, Proto: "TCP"})
	}

	s := New(db)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/captures/cap-1/packets?offset=0&limit=3", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp pageResponse[storage.PacketRecord]
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Items) != 3 {
		t.Errorf("Items len = %d, want 3", len(resp.Items))
	}
	if resp.Total != 10 {
		t.Errorf("Total = %d, want 10", resp.Total)
	}
	if resp.Items[0].No != 1 {
		t.Errorf("first No = %d, want 1", resp.Items[0].No)
	}
}
