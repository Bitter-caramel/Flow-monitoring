package alerting

// 环形告警缓冲：固定容量、满则淘汰最旧、并发安全。
//
// 语义（任务 15-2b 设计决定 B）：
//   - 每条告警分配单调递增 id（从 1 起）；
//   - 查询始终按 id 升序返回；
//   - 消费 goroutine（写）与 HTTP handler（读）并发 ⇒ 所有访问都过同一把锁。

import (
	"math"
	"sync"
)

// 分页与缓冲默认值。
const (
	// DefaultPageSize 是 /api/alerts 未显式给 page_size 时的默认值。
	DefaultPageSize = 50
	// MaxPageSize 是 page_size 的上限（超出按上限处理，不报错）。
	MaxPageSize = 500
	// DefaultAlertBuffer 是 ring 的默认容量（capacity <= 0 时使用）。
	DefaultAlertBuffer = 1000
)

// Page 是 /api/alerts 的响应体。
//
// ★ Items 必须是非 nil 切片：nil slice 会被 encoding/json 序列化成 null，
// 前端拿到 null 会白屏（踩过的坑）。
type Page struct {
	Items    []Alert `json:"items"`
	Page     int     `json:"page"`
	PageSize int     `json:"page_size"`
	Total    int     `json:"total"`
}

// 告警 mode 取值（前端工作台过滤用；阶段 2 里 live 是唯一实际产出的值）。
const (
	ModeLive   = "live"
	ModeStatic = "static"
)

// Filter 是告警查询的过滤条件。
//
// ★ 空字段表示"不过滤"：Mode=="" 不按 mode 筛，RunID=="" 不按 run_id 筛，
// 因此 Filter{} 等价于"返回全部"。
type Filter struct {
	Mode  string
	RunID string
}

// ring 是并发安全的固定容量环形缓冲。
type ring struct {
	mu    sync.Mutex
	items []Alert // 始终按 ID 升序
	cap   int
	// nextID 是下一条告警的 ID，从 1 起；只增不减（淘汰旧记录也不复用 ID）。
	nextID uint64
	// dropped 累计因满容量而被淘汰的旧记录数。
	dropped uint64
}

// newRing 创建容量为 capacity 的环形缓冲；capacity <= 0 时使用默认值。
func newRing(capacity int) *ring {
	if capacity <= 0 {
		capacity = DefaultAlertBuffer
	}
	return &ring{
		items:  make([]Alert, 0, capacity),
		cap:    capacity,
		nextID: 1,
	}
}

// add 分配新 ID、写入缓冲；满容量时淘汰最旧一条。
func (r *ring) add(a Alert) Alert {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec := a
	rec.ID = r.nextID
	r.nextID++

	if len(r.items) >= r.cap {
		// 淘汰最旧：整体左移一格，新记录写进末尾。
		copy(r.items, r.items[1:])
		r.items[len(r.items)-1] = rec
		r.dropped++
		return rec
	}
	r.items = append(r.items, rec)
	return rec
}

// query 按 id 升序返回一页告警（可选按 mode/run_id 过滤）。
//
// 语义：
//   - page 从 1 起（<=0 按 1 处理）；
//   - pageSize 默认 50、上限 500（<=0 用默认值）；
//   - sinceID > 0 时只返回 id > sinceID 的记录（增量拉取）；
//   - f 的空字段不过滤（Filter{} 等价于返回全部）；
//   - total 是经过 sinceID + Filter 过滤后的总数（翻页以它为准）；
//   - 越界页返回空数组（不是 nil，也不是错误）。
func (r *ring) query(page, pageSize int, sinceID uint64, f Filter) Page {
	r.mu.Lock()
	defer r.mu.Unlock()

	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}

	filtered := make([]Alert, 0, len(r.items))
	for _, it := range r.items {
		if it.ID <= sinceID {
			continue
		}
		// 空字段不过滤 ⇒ Filter{} 返回全部。
		if f.Mode != "" && it.Mode != f.Mode {
			continue
		}
		if f.RunID != "" && it.RunID != f.RunID {
			continue
		}
		filtered = append(filtered, it)
	}
	total := len(filtered)

	// 用 int64 计算起点，避免超大 page 在极端输入下乘法溢出。
	start64 := int64(0)
	if page > 1 {
		p := int64(page - 1)
		if p > math.MaxInt64/int64(pageSize) {
			start64 = math.MaxInt64
		} else {
			start64 = p * int64(pageSize)
		}
	}
	// end64 也要防溢出：start64 已达 MaxInt64 时不能再加 pageSize。
	end64 := int64(math.MaxInt64)
	if start64 <= math.MaxInt64-int64(pageSize) {
		end64 = start64 + int64(pageSize)
	}

	start := total
	if start64 < int64(total) {
		start = int(start64)
	}
	end := total
	if end64 < int64(total) {
		end = int(end64)
	}

	items := make([]Alert, 0, end-start)
	if start < end {
		items = append(items, filtered[start:end]...)
	}
	return Page{Items: items, Page: page, PageSize: pageSize, Total: total}
}

// len 返回当前缓冲中的告警条数。
func (r *ring) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.items)
}

// capacity 返回固定容量（构造后不变，无需加锁）。
func (r *ring) capacity() int { return r.cap }

// droppedCount 返回因满容量而淘汰的旧记录数。
func (r *ring) droppedCount() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropped
}

// groupCounts 遍历当前缓冲，返回按 mode / run_id 分组的条数。
//
// ★ 空值（""）不计数：旧载荷没有这些字段时不应虚增一个空 key。
// 返回值始终非 nil（空缓冲返回空 map），便于 JSON 序列化成 {} 而不是 null。
func (r *ring) groupCounts() (byMode, byRun map[string]int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	byMode = make(map[string]int)
	byRun = make(map[string]int)
	for _, it := range r.items {
		if it.Mode != "" {
			byMode[it.Mode]++
		}
		if it.RunID != "" {
			byRun[it.RunID]++
		}
	}
	return byMode, byRun
}
