package situation

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestEngine 构造一个窗口很长、阈值默认的引擎，便于逐条断言分数。
func newTestEngine() *engine {
	return newEngine(engineConfig{
		window: time.Minute,
		low:    30,
		medium: 100,
		high:   300,
	})
}

// findItem 从快照里按 IP 找一项。
func findItem(items []item, ip string) (item, bool) {
	for _, it := range items {
		if it.SrcIP == ip {
			return it, true
		}
	}
	return item{}, false
}

// TestEngineScoringBasic 三条 weight=80 ⇒ 240 分、3 次、3 个规则。
func TestEngineScoringBasic(t *testing.T) {
	e := newTestEngine()
	e.record("10.0.0.1", "r1", 80)
	e.record("10.0.0.1", "r2", 80)
	e.record("10.0.0.1", "r3", 80)

	items, _ := e.snapshot()
	it, ok := findItem(items, "10.0.0.1")
	if !ok {
		t.Fatalf("未找到 10.0.0.1: %+v", items)
	}
	if it.Score != 240 || it.Hits != 3 || it.Rules != 3 {
		t.Fatalf("score=%d hits=%d rules=%d, want 240/3/3", it.Score, it.Hits, it.Rules)
	}
	if it.Level != "medium" {
		t.Fatalf("level=%q, want medium（240 在 100~300）", it.Level)
	}
}

// TestEngineNotCapped 200 次 weight=80 ⇒ 16000 分（★ 不封顶，任何 ≤1000 的值都算失败）。
func TestEngineNotCapped(t *testing.T) {
	e := newTestEngine()
	for i := 0; i < 200; i++ {
		e.record("10.0.0.2", "r1", 80)
	}
	items, _ := e.snapshot()
	it, ok := findItem(items, "10.0.0.2")
	if !ok {
		t.Fatal("未找到 10.0.0.2")
	}
	if it.Score != 16000 {
		t.Fatalf("score=%d, want 16000（不封顶）", it.Score)
	}
	if it.Hits != 200 {
		t.Fatalf("hits=%d, want 200", it.Hits)
	}
	if it.Level != "high" {
		t.Fatalf("level=%q, want high", it.Level)
	}
}

// TestEngineAccumulatesSameRule 同一规则 5 次 ⇒ hits=5、score=400（★ 累计，不是去重）。
func TestEngineAccumulatesSameRule(t *testing.T) {
	e := newTestEngine()
	for i := 0; i < 5; i++ {
		e.record("10.0.0.3", "same-rule", 80)
	}
	items, _ := e.snapshot()
	it, _ := findItem(items, "10.0.0.3")
	if it.Hits != 5 || it.Score != 400 {
		t.Fatalf("hits=%d score=%d, want 5/400（同规则也要累计）", it.Hits, it.Score)
	}
	if it.Rules != 1 {
		t.Fatalf("rules=%d, want 1（去重后的规则种类）", it.Rules)
	}
}

// TestEngineLevelChangeOnlyOnTransition 等级不变时不重复产生事件。
func TestEngineLevelChangeOnlyOnTransition(t *testing.T) {
	e := newTestEngine()

	// 第一条 80 分 ⇒ none→low，产生 1 条
	ch := e.record("10.0.0.4", "r1", 80)
	if len(ch) != 1 || ch[0].Level != "low" || ch[0].Prev != "none" {
		t.Fatalf("第一次应产生 none→low 1 条，得到 %+v", ch)
	}
	// 第二条累加到 160 ⇒ 越过 medium 阈值(100)，应产生 low→medium 1 条
	ch = e.record("10.0.0.4", "r2", 80)
	if len(ch) != 1 || ch[0].Level != "medium" || ch[0].Prev != "low" {
		t.Fatalf("160 分应产生 low→medium 1 条，得到 %+v", ch)
	}
	// 第三条累加到 240，仍是 medium ⇒ 不产生
	ch = e.record("10.0.0.4", "r3", 80)
	if len(ch) != 0 {
		t.Fatalf("仍在 medium 时应无事件，得到 %+v", ch)
	}
	// 第四条累加到 320 ⇒ high
	ch = e.record("10.0.0.4", "r4", 80)
	if len(ch) != 1 || ch[0].Level != "high" {
		t.Fatalf("跨到 high 应产生 1 条，得到 %+v", ch)
	}
}

// TestEngineWindowExpiry 窗口过期后该 IP 被移除。
func TestEngineWindowExpiry(t *testing.T) {
	e := newEngine(engineConfig{window: 50 * time.Millisecond, low: 30, medium: 100, high: 300})
	e.record("10.0.0.5", "r1", 80)

	if items, _ := e.snapshot(); len(items) != 1 {
		t.Fatalf("刚记录后应有 1 项，得到 %d", len(items))
	}
	time.Sleep(80 * time.Millisecond)

	items, _ := e.snapshot()
	if len(items) != 0 {
		t.Fatalf("窗口过期后应为空，得到 %+v", items)
	}
	if st := e.stats(); st.TrackedIPs != 0 {
		t.Fatalf("tracked_ips=%d, want 0", st.TrackedIPs)
	}
}

// TestHandlerEmptyItemsIsArray 无数据时 items 必须是 []，不能是 null。
func TestHandlerEmptyItemsIsArray(t *testing.T) {
	m := newModule()
	rec := httptest.NewRecorder()
	m.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/situation", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d, want 200", rec.Code)
	}
	var body struct {
		Items []item `json:"items"`
		Total int    `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析响应失败: %v (%s)", err, rec.Body.String())
	}
	if body.Items == nil {
		t.Fatalf("items 是 null，必须是 []（body=%s）", rec.Body.String())
	}
	if len(body.Items) != 0 || body.Total != 0 {
		t.Fatalf("items=%d total=%d, want 0/0", len(body.Items), body.Total)
	}
}
