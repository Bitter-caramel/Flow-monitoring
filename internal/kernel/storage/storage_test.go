package storage

import (
	"context"
	"errors"
	"sort"
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

// ListByEndpoints 内存替身：把已存的所有 capture 的包中匹配 (ep1→ep2) 或
// (ep2→ep1) 的挑出来，按 (Time, CaptureID, No) 升序排序并分页。
// Total 与 ListByCapture 保持一致，返回匹配总数（真值，非 -1）。
func (s *memPacketStore) ListByEndpoints(_ context.Context, ep1, ep2 Endpoint, page Page) (*PageResult[PacketRecord], error) {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	var all []PacketRecord
	for _, pkts := range s.m.packets {
		for _, pk := range pkts {
			src := Endpoint{IP: pk.SrcIP, Port: pk.SrcPort}
			dst := Endpoint{IP: pk.DstIP, Port: pk.DstPort}
			if (src == ep1 && dst == ep2) || (src == ep2 && dst == ep1) {
				all = append(all, pk)
			}
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if !all[i].Time.Equal(all[j].Time) {
			return all[i].Time.Before(all[j].Time)
		}
		if all[i].CaptureID != all[j].CaptureID {
			return all[i].CaptureID < all[j].CaptureID
		}
		return all[i].No < all[j].No
	})
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

// TestPacketStore_ListByEndpoints 按四元组双向查包：双向、对称、排序、分页、空结果。
func TestPacketStore_ListByEndpoints(t *testing.T) {
	ctx := context.Background()
	epA := Endpoint{IP: "10.0.0.1", Port: 1234}
	epB := Endpoint{IP: "10.0.0.2", Port: 80}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	s := newMemStorage()
	// ★ ListByEndpoints 是**可选扩展**（PacketFlowQuerier），不在 PacketStore 里 ⇒
	// 按「能力探测」的方式拿；拿不到说明替身没实现该能力。
	q, ok := s.Packets().(PacketFlowQuerier)
	if !ok {
		t.Fatal("memPacketStore 未实现可选扩展 PacketFlowQuerier")
	}
	// 乱序插入 + 跨 capture + 干扰包（不同源 IP）。
	if err := s.Packets().SaveBatch(ctx, "cap-b", []PacketRecord{
		{CaptureID: "cap-b", No: 2, Time: base.Add(3 * time.Second), SrcIP: epA.IP, SrcPort: epA.Port, DstIP: epB.IP, DstPort: epB.Port, Proto: "TCP"},
		{CaptureID: "cap-b", No: 1, Time: base.Add(1 * time.Second), SrcIP: epB.IP, SrcPort: epB.Port, DstIP: epA.IP, DstPort: epA.Port, Proto: "TCP"},
	}); err != nil {
		t.Fatalf("SaveBatch cap-b: %v", err)
	}
	if err := s.Packets().SaveBatch(ctx, "cap-a", []PacketRecord{
		{CaptureID: "cap-a", No: 5, Time: base.Add(2 * time.Second), SrcIP: epA.IP, SrcPort: epA.Port, DstIP: epB.IP, DstPort: epB.Port, Proto: "TCP"},
		{CaptureID: "cap-a", No: 9, Time: base.Add(2 * time.Second), SrcIP: "10.0.0.9", SrcPort: 9999, DstIP: epB.IP, DstPort: epB.Port, Proto: "TCP"},
	}); err != nil {
		t.Fatalf("SaveBatch cap-a: %v", err)
	}

	// 1. 只返回目标连接，且两个方向都在。
	res, err := q.ListByEndpoints(ctx, epA, epB, Page{Limit: 100})
	if err != nil {
		t.Fatalf("ListByEndpoints: %v", err)
	}
	if len(res.Items) != 3 {
		t.Fatalf("Items len = %d, want 3", len(res.Items))
	}
	if res.Total != 3 {
		t.Errorf("Total = %d, want 3", res.Total)
	}
	var sawAB, sawBA bool
	for _, it := range res.Items {
		if it.SrcIP == epA.IP && it.SrcPort == epA.Port {
			sawAB = true
		}
		if it.SrcIP == epB.IP && it.SrcPort == epB.Port {
			sawBA = true
		}
	}
	if !sawAB || !sawBA {
		t.Errorf("both directions should be present: ab=%v ba=%v", sawAB, sawBA)
	}

	// 2. 对称性：(epA,epB) 与 (epB,epA) 结果相同。
	rev, err := q.ListByEndpoints(ctx, epB, epA, Page{Limit: 100})
	if err != nil {
		t.Fatalf("reverse ListByEndpoints: %v", err)
	}
	if len(rev.Items) != len(res.Items) {
		t.Fatalf("reverse len = %d, want %d", len(rev.Items), len(res.Items))
	}
	for i := range rev.Items {
		if rev.Items[i] != res.Items[i] {
			t.Errorf("item[%d] mismatch: %+v vs %+v", i, rev.Items[i], res.Items[i])
		}
	}

	// 3. 排序按 (Time, CaptureID, No) 升序。
	want := []struct {
		cap string
		no  int
	}{{"cap-b", 1}, {"cap-a", 5}, {"cap-b", 2}}
	for i, w := range want {
		if res.Items[i].CaptureID != w.cap || res.Items[i].No != w.no {
			t.Errorf("item[%d] = %s/%d, want %s/%d", i, res.Items[i].CaptureID, res.Items[i].No, w.cap, w.no)
		}
	}

	// 4. page.Limit = 1 只返回 1 条。
	one, err := q.ListByEndpoints(ctx, epA, epB, Page{Limit: 1})
	if err != nil {
		t.Fatalf("ListByEndpoints limit=1: %v", err)
	}
	if len(one.Items) != 1 {
		t.Errorf("limit=1 len = %d, want 1", len(one.Items))
	}
	if one.Total != 3 {
		t.Errorf("limit=1 Total = %d, want 3", one.Total)
	}

	// 5. 查不存在的连接 ⇒ Items 为空且 err == nil。
	none, err := q.ListByEndpoints(ctx, Endpoint{IP: "1.1.1.1", Port: 1}, Endpoint{IP: "2.2.2.2", Port: 2}, Page{Limit: 10})
	if err != nil {
		t.Fatalf("missing conn err = %v, want nil", err)
	}
	if len(none.Items) != 0 {
		t.Errorf("missing conn len = %d, want 0", len(none.Items))
	}
	if none.Total != 0 {
		t.Errorf("missing conn Total = %d, want 0", none.Total)
	}
}
