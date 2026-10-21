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
	p := r.query(1, 50, 0, Filter{})
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
	if p := r.query(1, 50, 0, Filter{}); p.Items[0].ID != 4 || p.Items[2].ID != 6 {
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
			p := r.query(c.page, c.size, 0, Filter{})
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
	p := r.query(int(^uint(0)>>1), 3, 0, Filter{})
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

	p := r.query(1, 50, 3, Filter{})
	if p.Total != 2 || len(p.Items) != 2 || p.Items[0].ID != 4 || p.Items[1].ID != 5 {
		t.Fatalf("since_id=3 total=%d items=%v, want 2 / [4 5]", p.Total, idsOf(p.Items))
	}

	p = r.query(1, 50, 99, Filter{})
	if p.Total != 0 || len(p.Items) != 0 {
		t.Fatalf("since_id=99 total=%d items=%v, want 0/空", p.Total, idsOf(p.Items))
	}
	if p.Items == nil {
		t.Fatal("Items 为 nil，必须是非 nil 空数组（否则 JSON 序列化成 null）")
	}
}

// TestRingEmptyItemsIsNonNil 空缓冲查询也必须是 [] 而不是 null。
func TestRingEmptyItemsIsNonNil(t *testing.T) {
	p := newRing(1).query(1, DefaultPageSize, 0, Filter{})
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
				if r.query(1, 20, 0, Filter{}).Items == nil {
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
	p := r.query(1, MaxPageSize, 0, Filter{})
	if p.Total != 50 {
		t.Fatalf("total = %d, want 50", p.Total)
	}
	// 800 次写入后应保留 ID 751..800（连续、升序）。
	if p.Items[0].ID != 751 || p.Items[49].ID != 800 {
		t.Fatalf("IDs = [%d..%d], want [751..800]", p.Items[0].ID, p.Items[49].ID)
	}
}

// TestRingQueryFilter 验证 mode/run_id 过滤：
//   - Filter{} 空 ⇒ 返回全部；
//   - 单条件 / 组合条件精确筛选；
//   - total 必须是"过滤后"的条数（翻页以它为准），而不是过滤前。
func TestRingQueryFilter(t *testing.T) {
	r := newRing(100)
	type meta struct{ mode, run string }
	metas := []meta{
		{ModeLive, "run-1"},
		{ModeLive, "run-2"},
		{ModeStatic, "run-1"},
		{ModeStatic, "run-3"},
		{"", ""}, // 旧载荷：无归属，任何带条件过滤都不应命中
	}
	for i, m := range metas {
		a := mkAlert(fmt.Sprintf("r%d", i))
		a.Mode = m.mode
		a.RunID = m.run
		r.add(a)
	}

	cases := []struct {
		name string
		f    Filter
		want []uint64
	}{
		{"空 Filter 返回全部", Filter{}, []uint64{1, 2, 3, 4, 5}},
		{"mode=live", Filter{Mode: ModeLive}, []uint64{1, 2}},
		{"mode=static", Filter{Mode: ModeStatic}, []uint64{3, 4}},
		{"run_id=run-1", Filter{RunID: "run-1"}, []uint64{1, 3}},
		{"mode+run_id 组合", Filter{Mode: ModeStatic, RunID: "run-1"}, []uint64{3}},
		{"未知 run_id", Filter{RunID: "run-9"}, []uint64{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := r.query(1, MaxPageSize, 0, c.f)
			if p.Total != len(c.want) {
				t.Fatalf("total = %d, want %d（total 应是过滤后的条数）", p.Total, len(c.want))
			}
			got := idsOf(p.Items)
			if len(got) != len(c.want) {
				t.Fatalf("ids = %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("ids = %v, want %v", got, c.want)
				}
			}
		})
	}

	// 过滤后分页：total 反映过滤后的总数（2），但一页只返回 1 条。
	p := r.query(1, 1, 0, Filter{Mode: ModeLive})
	if p.Total != 2 {
		t.Fatalf("过滤后分页 total = %d, want 2", p.Total)
	}
	if len(p.Items) != 1 || p.Items[0].ID != 1 {
		t.Fatalf("过滤后分页 items = %v, want 仅首条 [1]", idsOf(p.Items))
	}
}

// TestRingQueryCaptureIDFilter 验证 capture_id 过滤（任务 16-6）：
//   - 两条告警分属不同 capture_id ⇒ Filter{CaptureID:"A"} 只回 A；
//   - total 必须是过滤后的条数，而不是过滤前的全部；
//   - CaptureID 与 mode/run_id 组合时同样生效；
//   - CaptureID=="" 不过滤。
func TestRingQueryCaptureIDFilter(t *testing.T) {
	r := newRing(100)
	metas := []struct{ mode, run, capture string }{
		{ModeStatic, "run-a", "cap-A"},
		{ModeStatic, "run-b", "cap-B"},
		{ModeStatic, "run-a", "cap-A"},
		{ModeLive, "run-live", ""},
	}
	for i, m := range metas {
		a := mkAlert(fmt.Sprintf("r%d", i))
		a.Mode = m.mode
		a.RunID = m.run
		a.CaptureID = m.capture
		r.add(a)
	}

	cases := []struct {
		name string
		f    Filter
		want []uint64
	}{
		{"capture_id=A", Filter{CaptureID: "cap-A"}, []uint64{1, 3}},
		{"capture_id=B", Filter{CaptureID: "cap-B"}, []uint64{2}},
		{"capture_id 与 mode 组合", Filter{Mode: ModeStatic, CaptureID: "cap-A"}, []uint64{1, 3}},
		{"capture_id 与 run_id 组合", Filter{RunID: "run-a", CaptureID: "cap-A"}, []uint64{1, 3}},
		{"未知 capture_id", Filter{CaptureID: "cap-X"}, []uint64{}},
		{"空 capture_id 不过滤", Filter{CaptureID: ""}, []uint64{1, 2, 3, 4}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := r.query(1, MaxPageSize, 0, c.f)
			if p.Total != len(c.want) {
				t.Fatalf("total = %d, want %d（total 应是过滤后的条数）", p.Total, len(c.want))
			}
			got := idsOf(p.Items)
			if len(got) != len(c.want) {
				t.Fatalf("ids = %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("ids = %v, want %v", got, c.want)
				}
			}
		})
	}

	// 过滤后分页：total 反映 cap-A 的 2 条，但一页只返回 1 条。
	p := r.query(1, 1, 0, Filter{CaptureID: "cap-A"})
	if p.Total != 2 {
		t.Fatalf("过滤后分页 total = %d, want 2", p.Total)
	}
	if len(p.Items) != 1 || p.Items[0].ID != 1 {
		t.Fatalf("过滤后分页 items = %v, want 仅首条 [1]", idsOf(p.Items))
	}
}
