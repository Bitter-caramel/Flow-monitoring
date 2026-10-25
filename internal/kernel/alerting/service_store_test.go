package alerting

// 任务 C1：批量落库（Store != nil）的宿主侧测试。
//
// 覆盖：
//  1) 批量写：投递 250 条 ⇒ 至少触发 1 次批量 INSERT，persisted == 250；
//  2) ID 一致性：落库后 Alert.ID 等于 DB 返回的 id，Query（查库）按 since_id 正确增量；
//  3) 失败重试：假 Store 首次返回错误 ⇒ 该批重试成功、persist_errors >= 1、数据不丢不重；
//  4) Store == nil ⇒ 退回内存自增 id 模式（与旧行为一致）。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/eventbus"
	"flow-monitoring/internal/kernel/storage"
)

// fakeAlertStore 是 AlertStore 的内存替身：
//   - 分配从 startID 起的递增 id（模拟 DB 的 BIGSERIAL）；
//   - InsertAlerts 可配置失败次数（失败时一行都不写入，保持"原子 INSERT"语义）；
//   - QueryAlerts 复用 ring.query 的过滤/分页语义，便于断言 since_id 增量。
//
// ★ 同时实现 storage.Storage 的其余方法（返回 nil），因为 Config.Store 是聚合接口。
type fakeAlertStore struct {
	mu   sync.Mutex
	next uint64
	ring *ring
	// failRemaining 是接下来 InsertAlerts 还要失败的次数。
	failRemaining int
	// inserts 是成功写入的批次数；batchSizes 记录每批大小。
	inserts    int
	batchSizes []int
	// inserted 是成功写入的告警总条数（用于断言"不丢 / 不重复"）。
	inserted int
}

func newFakeAlertStore(startID uint64) *fakeAlertStore {
	return &fakeAlertStore{next: startID, ring: newRing(1 << 20)}
}

func (f *fakeAlertStore) InsertAlerts(_ context.Context, alerts []Alert) ([]uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failRemaining > 0 {
		f.failRemaining--
		return nil, errors.New("fake: insert failed")
	}
	ids := make([]uint64, len(alerts))
	for i := range alerts {
		a := alerts[i]
		a.ID = f.next
		f.next++
		ids[i] = a.ID
		f.ring.addWithID(a)
	}
	f.inserts++
	f.batchSizes = append(f.batchSizes, len(alerts))
	f.inserted += len(alerts)
	return ids, nil
}

func (f *fakeAlertStore) QueryAlerts(_ context.Context, q AlertQuery) ([]Alert, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.ring.query(q.Page, q.PageSize, q.SinceID,
		Filter{Mode: q.Mode, RunID: q.RunID, CaptureID: q.CaptureID})
	return p.Items, p.Total, nil
}

// storage.Storage 的其余方法：本替身只用于告警，不需要 capture / packet。
func (f *fakeAlertStore) Captures() storage.CaptureStore { return nil }
func (f *fakeAlertStore) Packets() storage.PacketStore   { return nil }
func (f *fakeAlertStore) Close() error                   { return nil }

func (f *fakeAlertStore) snapshot() (inserts, inserted int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.inserts, f.inserted
}

// TestServicePersistsBatch250 投递 250 条 ⇒ 至少 1 次批量写，persisted == 250，一条不丢。
func TestServicePersistsBatch250(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	store := newFakeAlertStore(1)
	svc := New(Config{Capacity: 1000, Store: store})
	svc.Start(bus, "detect.feature")
	defer svc.Stop()

	const n = 250
	for i := 0; i < n; i++ {
		if err := bus.Publish("detect.feature", alertJSON(fmt.Sprintf("r%d", i))); err != nil {
			t.Fatalf("Publish #%d: %v", i, err)
		}
	}
	waitFor(t, 5*time.Second, func() bool { return svc.Stats().Persisted == n })

	st := svc.Stats()
	if st.Persisted != n {
		t.Fatalf("persisted = %d, want %d", st.Persisted, n)
	}
	if st.PersistErrors != 0 {
		t.Errorf("persist_errors = %d, want 0", st.PersistErrors)
	}
	inserts, inserted := store.snapshot()
	if inserts < 1 {
		t.Fatalf("批量写次数 = %d, want >= 1（必须走批量 INSERT）", inserts)
	}
	if inserted != n {
		t.Fatalf("库内条数 = %d, want %d（一条不丢）", inserted, n)
	}
}

// TestServicePersistIDConsistencyAndSinceID 落库 id 回填到内存，Query/since_id 增量正确。
func TestServicePersistIDConsistencyAndSinceID(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	store := newFakeAlertStore(1000) // DB 从 1000 起分配，明显区别于内存自增的 1
	svc := New(Config{Capacity: 100, PushBuffer: 64, Store: store})
	got := make(chan Alert, 16)
	svc.SetOnAlert(func(a Alert) { got <- a })
	svc.Start(bus, "detect.feature")
	defer svc.Stop()

	for i := 0; i < 3; i++ {
		if err := bus.Publish("detect.feature", alertJSON(fmt.Sprintf("r%d", i))); err != nil {
			t.Fatalf("Publish #%d: %v", i, err)
		}
	}
	waitFor(t, 5*time.Second, func() bool { return svc.Stats().Persisted == 3 })

	// OnAlert 收到的 id 必须等于 DB 返回的 id（1000/1001/1002），证明已回填。
	wantIDs := []uint64{1000, 1001, 1002}
	seen := make([]uint64, 0, 3)
	timeout := time.After(3 * time.Second)
	for len(seen) < 3 {
		select {
		case a := <-got:
			seen = append(seen, a.ID)
		case <-timeout:
			t.Fatalf("OnAlert 只收到 %d 条，want 3", len(seen))
		}
	}
	for i, id := range seen {
		if id != wantIDs[i] {
			t.Errorf("OnAlert[%d].ID = %d, want %d（内存 id 必须等于 DB id）", i, id, wantIDs[i])
		}
	}

	// Query（走库）按 id 升序返回全部。
	p := svc.Query(1, MaxPageSize, 0, Filter{})
	if p.Total != 3 || len(p.Items) != 3 {
		t.Fatalf("Query total=%d items=%d, want 3/3", p.Total, len(p.Items))
	}
	for i, a := range p.Items {
		if a.ID != wantIDs[i] {
			t.Errorf("Query items[%d].ID = %d, want %d（按 id 升序）", i, a.ID, wantIDs[i])
		}
	}

	// since_id 增量：id > 1000 ⇒ 只剩 1001/1002。
	p2 := svc.Query(1, MaxPageSize, 1000, Filter{})
	if p2.Total != 2 || len(p2.Items) != 2 {
		t.Fatalf("since_id=1000 total=%d items=%d, want 2/2", p2.Total, len(p2.Items))
	}
	if p2.Items[0].ID != 1001 || p2.Items[1].ID != 1002 {
		t.Errorf("since_id=1000 返回 ids = [%d %d], want [1001 1002]",
			p2.Items[0].ID, p2.Items[1].ID)
	}
}

// TestServicePersistRetriesWithoutLoss 假 Store 首次失败 ⇒ 重试成功、persist_errors>=1、不丢不重。
func TestServicePersistRetriesWithoutLoss(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	store := newFakeAlertStore(500)
	store.failRemaining = 1 // 第一次 InsertAlerts 返回错误
	svc := New(Config{Capacity: 100, Store: store})
	svc.Start(bus, "detect.feature")
	defer svc.Stop()

	const n = 5
	for i := 0; i < n; i++ {
		if err := bus.Publish("detect.feature", alertJSON(fmt.Sprintf("r%d", i))); err != nil {
			t.Fatalf("Publish #%d: %v", i, err)
		}
	}
	waitFor(t, 5*time.Second, func() bool { return svc.Stats().Persisted == n })

	st := svc.Stats()
	if st.PersistErrors < 1 {
		t.Errorf("persist_errors = %d, want >= 1（首次失败必须被计数）", st.PersistErrors)
	}
	_, inserted := store.snapshot()
	if inserted != n {
		t.Fatalf("库内条数 = %d, want %d（失败后重试：不丢也不重复）", inserted, n)
	}
	if p := svc.Query(1, MaxPageSize, 0, Filter{}); p.Total != n {
		t.Errorf("Query total = %d, want %d", p.Total, n)
	}
}

// TestServiceMemoryModeWhenStoreNil Store==nil ⇒ 退回内存自增 id，persist 统计全为 0。
func TestServiceMemoryModeWhenStoreNil(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	svc := New(Config{Capacity: 100})
	svc.Start(bus, "detect.feature")
	defer svc.Stop()

	for i := 0; i < 2; i++ {
		if err := bus.Publish("detect.feature", alertJSON(fmt.Sprintf("m%d", i))); err != nil {
			t.Fatalf("Publish #%d: %v", i, err)
		}
	}
	waitFor(t, 2*time.Second, func() bool { return svc.Stats().AlertsTotal == 2 })

	p := svc.Query(1, 10, 0, Filter{})
	if p.Total != 2 || len(p.Items) != 2 {
		t.Fatalf("Query total=%d items=%d, want 2/2", p.Total, len(p.Items))
	}
	for i, a := range p.Items {
		if a.ID != uint64(i+1) {
			t.Errorf("items[%d].ID = %d, want %d（内存模式自增 id）", i, a.ID, i+1)
		}
	}
	st := svc.Stats()
	if st.Persisted != 0 || st.PersistErrors != 0 || st.Pending != 0 {
		t.Errorf("内存模式 persist 统计应全为 0，实际 persisted=%d errors=%d pending=%d",
			st.Persisted, st.PersistErrors, st.Pending)
	}
}

// TestStatsJSONIncludesPersistFields /api/alerts/stats 必须暴露 C1 新增的三个字段。
func TestStatsJSONIncludesPersistFields(t *testing.T) {
	svc := New(Config{Capacity: 10})
	b, err := json.Marshal(svc.Stats())
	if err != nil {
		t.Fatalf("Marshal Stats: %v", err)
	}
	for _, key := range []string{`"persisted"`, `"persist_errors"`, `"pending"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("stats JSON 缺少字段 %s: %s", key, string(b))
		}
	}
}
