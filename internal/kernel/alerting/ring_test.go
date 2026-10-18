package alerting

import (
	"fmt"
	"sync"
	"testing"
)

func mkAlert(ruleID string) Alert {
	return Alert{
		RuleID:   ruleID,
		Name:     ruleID + " name",
		Severity: "high",
		Weight:   80,
		SrcIP:    "10.0.0.1",
		DstIP:    "10.0.0.2",
		Proto:    "HTTP",
	}
}

func idsOf(items []Alert) []uint64 {
	out := make([]uint64, len(items))
	for i, a := range items {
		out[i] = a.ID
	}
	return out
}

// TestRingEvictsOldest 满容量后淘汰最旧，且 ID 继续单调递增（不复用）。
func TestRingEvictsOldest(t *testing.T) {
	r := newRing(3)
	for i := 1; i <= 5; i++ {
		rec := r.add(mkAlert(fmt.Sprintf("r%d", i)))
		if rec.ID != uint64(i) {
			t.Fatalf("第 %d 条告警 ID = %d, want %d", i, rec.ID, i)
		}
	}
	if got := r.len(); got != 3 {
		t.Fatalf("len = %d, want 3", got)
	}
	if got := r.droppedCount(); got != 2 {
		t.Fatalf("dropped = %d, want 2", got)
	}
	p := r.query(1, 50, 0)
	if p.Total != 3 {
		t.Fatalf("total = %d, want 3", p.Total)
	}
	wantIDs := []uint64{3, 4, 5}
	for i, a := range p.Items {
		if a.ID != wantIDs[i] {
			t.Fatalf("items[%d].ID = %d, want %d（应淘汰最旧的 1,2）", i, a.ID, wantIDs[i])
		}
	}
	// 淘汰后新记录的 ID 必须继续递增，不能复用 1/2。
	if rec := r.add(mkAlert("r6")); rec.ID != 6 {
		t.Fatalf("new ID = %d, want 6", rec.ID)
	}
	if p := r.query(1, 50, 0); p.Items[0].ID != 4 || p.Items[2].ID != 6 {
		t.Fatalf("淘汰后 IDs = %v, want [4 5 6]", idsOf(p.Items))
	}
}

// TestRingPaginationBounds 分页边界：page=0、超大 page_size、越界页、非法 page_size。
func TestRingPaginationBounds(t *testing.T) {
	r := newRing(100)
	for i := 0; i < 10; i++ {
		r.add(mkAlert(fmt.Sprintf("r%d", i)))
	}

	cases := []struct {
		name      string
		page      int
		size      int
		wantPage  int
		wantSize  int
		wantIDs   []uint64
		wantTotal int
	}{
		{"page=0 归一到 1", 0, 3, 1, 3, []uint64{1, 2, 3}, 10},
		{"第二页", 2, 3, 2, 3, []uint64{4, 5, 6}, 10},
		{"最后一页不足一页", 4, 3, 4, 3, []uint64{10}, 10},
		{"越界页返回空数组", 99, 3, 99, 3, []uint64{}, 10},
		{"page_size=0 用默认 50", 1, 0, 1, DefaultPageSize, []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 10},
		{"负 page_size 用默认 50", 1, -5, 1, DefaultPageSize, []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 10},
		{"超大 page_size 截到 500", 1, 99999, 1, MaxPageSize, []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 10},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := r.query(c.page, c.size, 0)
			if p.Page != c.wantPage || p.PageSize != c.wantSize || p.Total != c.wantTotal {
				t.Fatalf("Page=%d PageSize=%d Total=%d, want %d/%d/%d",
					p.Page, p.PageSize, p.Total, c.wantPage, c.wantSize, c.wantTotal)
			}
			got := idsOf(p.Items)
			if len(got) != len(c.wantIDs) {
				t.Fatalf("Items IDs = %v, want %v", got, c.wantIDs)
			}
			for i := range got {
				if got[i] != c.wantIDs[i] {
					t.Fatalf("Items IDs = %v, want %v", got, c.wantIDs)
				}
			}
		})
	}
}

// TestRingExtremePageNoOverflow 极端 page（MaxInt）不能因乘法/加法溢出而 panic。
func TestRingExtremePageNoOverflow(t *testing.T) {
	r := newRing(10)
	for i := 0; i < 10; i++ {
		r.add(mkAlert("x"))
	}
	p := r.query(int(^uint(0)>>1), 3, 0)
	if p.Total != 10 {
		t.Fatalf("total = %d, want 10", p.Total)
	}
	if p.Items == nil || len(p.Items) != 0 {
		t.Fatalf("极端 page 应返回空数组，got %v", idsOf(p.Items))
	}
}

// TestRingSinceID since_id > 0 时只返回 id > since_id 的告警。
func TestRingSinceID(t *testing.T) {
	r := newRing(10)
	for i := 0; i < 5; i++ {
		r.add(mkAlert(fmt.Sprintf("r%d", i)))
	}

	p := r.query(1, 50, 3)
	if p.Total != 2 || len(p.Items) != 2 || p.Items[0].ID != 4 || p.Items[1].ID != 5 {
		t.Fatalf("since_id=3 total=%d items=%v, want 2 / [4 5]", p.Total, idsOf(p.Items))
	}

	p = r.query(1, 50, 99)
	if p.Total != 0 || len(p.Items) != 0 {
		t.Fatalf("since_id=99 total=%d items=%v, want 0/空", p.Total, idsOf(p.Items))
	}
	if p.Items == nil {
		t.Fatal("Items 为 nil，必须是非 nil 空数组（否则 JSON 序列化成 null）")
	}
}

// TestRingEmptyItemsIsNonNil 空缓冲查询也必须是 [] 而不是 null。
func TestRingEmptyItemsIsNonNil(t *testing.T) {
	p := newRing(1).query(1, DefaultPageSize, 0)
	if p.Items == nil {
		t.Fatal("空缓冲的 Items 为 nil，必须是非 nil 空数组")
	}
	if len(p.Items) != 0 {
		t.Fatalf("len(Items) = %d, want 0", len(p.Items))
	}
}

// TestRingDefaultCapacityAndIDStart 容量 <=0 用默认值；ID 从 1 起。
func TestRingDefaultCapacityAndIDStart(t *testing.T) {
	r := newRing(0)
	if r.capacity() != DefaultAlertBuffer {
		t.Fatalf("capacity = %d, want %d", r.capacity(), DefaultAlertBuffer)
	}
	if rec := r.add(mkAlert("first")); rec.ID != 1 {
		t.Fatalf("first ID = %d, want 1", rec.ID)
	}
}

// TestRingConcurrentReadWrite 覆盖“消费 goroutine 写、HTTP 读”的并发场景。
func TestRingConcurrentReadWrite(t *testing.T) {
	r := newRing(50)
	const writers = 4
	const perWriter = 200

	var wg sync.WaitGroup
	wg.Add(writers)
	for w := 0; w < writers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				r.add(mkAlert("concurrent"))
			}
		}()
	}

	stop := make(chan struct{})
	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
				if r.query(1, 20, 0).Items == nil {
					t.Error("并发读时 Items 为 nil")
					return
				}
			}
		}
	}()

	wg.Wait()
	close(stop)
	readerWG.Wait()

	if got := r.len(); got != 50 {
		t.Fatalf("len = %d, want 50（容量上限）", got)
	}
	p := r.query(1, MaxPageSize, 0)
	if p.Total != 50 {
		t.Fatalf("total = %d, want 50", p.Total)
	}
	// 800 次写入后应保留 ID 751..800（连续、升序）。
	if p.Items[0].ID != 751 || p.Items[49].ID != 800 {
		t.Fatalf("IDs = [%d..%d], want [751..800]", p.Items[0].ID, p.Items[49].ID)
	}
}
