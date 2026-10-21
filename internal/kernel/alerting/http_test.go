package alerting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/eventbus"
)

// muxRegistrar 把 *http.ServeMux 适配到 Registrar。
// （ServeMux.HandleFunc 的第二个参数是未命名函数类型，与 http.HandlerFunc 不同，
// 因此 ServeMux 本身不直接满足接口；生产侧 *transport.Server 的签名是一致的。）
type muxRegistrar struct{ mux *http.ServeMux }

func (m muxRegistrar) HandleFunc(pattern string, fn http.HandlerFunc) {
	m.mux.HandleFunc(pattern, fn)
}

// newHTTPTestServer 把 Service 的两条路由挂到测试 mux 上。
func newHTTPTestServer(t *testing.T, svc *Service) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	svc.Register(muxRegistrar{mux: mux})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func getJSON(t *testing.T, url string, out any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}

// TestAlertsHTTPEmptyItemsIsArray 空缓冲时 items 必须是 []，不能是 null。
func TestAlertsHTTPEmptyItemsIsArray(t *testing.T) {
	svc := New(Config{Capacity: 10})
	ts := newHTTPTestServer(t, svc)

	resp, err := http.Get(ts.URL + "/api/alerts")
	if err != nil {
		t.Fatalf("GET /api/alerts: %v", err)
	}
	defer resp.Body.Close()

	var raw struct {
		Items json.RawMessage `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := strings.TrimSpace(string(raw.Items)); got != "[]" {
		t.Fatalf("items = %s, want []（nil slice 会序列化成 null，前端会白屏）", got)
	}
}

// TestAlertsHTTPEmptyBodyShape 直接断言响应体中的 items 是数组字面量。
func TestAlertsHTTPEmptyBodyShape(t *testing.T) {
	svc := New(Config{Capacity: 10})
	ts := newHTTPTestServer(t, svc)

	resp, err := http.Get(ts.URL + "/api/alerts?since_id=999")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(buf.String(), `"items":[]`) {
		t.Fatalf("body = %s, want 包含 \"items\":[]", buf.String())
	}
}

// TestAlertsStatsFieldsComplete stats 字段齐全，且不再含宿主不知道的 rules/replay 字段。
func TestAlertsStatsFieldsComplete(t *testing.T) {
	svc := New(Config{Capacity: 10})
	ts := newHTTPTestServer(t, svc)

	var m map[string]json.RawMessage
	getJSON(t, ts.URL+"/api/alerts/stats", &m)

	for _, k := range []string{
		"enabled", "alerts_total", "capacity",
		"received", "dropped", "decode_errors", "last_error",
	} {
		if _, ok := m[k]; !ok {
			t.Errorf("stats 缺少字段 %q", k)
		}
	}
	// ★ 15-2b：宿主不再加载规则、不再跑回放，这些字段必须移除。
	for _, k := range []string{"rules_total", "rules_by_source", "replay", "issues"} {
		if _, ok := m[k]; ok {
			t.Errorf("stats 不应再含字段 %q（宿主不知道这些信息，留着就是撒谎）", k)
		}
	}

	var st Stats
	if err := json.Unmarshal(mustMarshal(t, m), &st); err != nil {
		t.Fatalf("decode Stats: %v", err)
	}
	if st.Capacity != 10 {
		t.Errorf("capacity = %d, want 10", st.Capacity)
	}
}

// TestAlertsHTTPAfterPublish 通过总线投 3 条后 HTTP 查询：分页、since_id、page_size 上限。
func TestAlertsHTTPAfterPublish(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	svc := New(Config{Capacity: 1000})
	svc.Start(bus, "detect.feature")
	t.Cleanup(svc.Stop)

	for i := 1; i <= 3; i++ {
		if err := bus.Publish("detect.feature", alertJSON(fmt.Sprintf("r%d", i))); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}
	waitFor(t, 2*time.Second, func() bool { return svc.Stats().AlertsTotal == 3 })

	ts := newHTTPTestServer(t, svc)

	var page Page
	getJSON(t, ts.URL+"/api/alerts", &page)
	if page.Total != 3 || len(page.Items) != 3 {
		t.Fatalf("total=%d items=%d, want 3/3", page.Total, len(page.Items))
	}
	for i, a := range page.Items {
		if a.ID != uint64(i+1) {
			t.Errorf("items[%d].ID = %d, want %d", i, a.ID, i+1)
		}
	}

	// since_id 增量：只要 id > 2 的一条。
	var inc Page
	getJSON(t, ts.URL+"/api/alerts?since_id=2", &inc)
	if inc.Total != 1 || len(inc.Items) != 1 || inc.Items[0].ID != 3 {
		t.Fatalf("since_id=2 total=%d items=%v, want total=1 id=3", inc.Total, idsOf(inc.Items))
	}

	// page=0 归一到 1；超大 page_size 截到 500。
	var clamped Page
	getJSON(t, ts.URL+"/api/alerts?page=0&page_size=99999", &clamped)
	if clamped.Page != 1 || clamped.PageSize != MaxPageSize {
		t.Fatalf("page=%d page_size=%d, want 1/%d", clamped.Page, clamped.PageSize, MaxPageSize)
	}

	// stats 应反映消费结果。
	var st Stats
	getJSON(t, ts.URL+"/api/alerts/stats", &st)
	if !st.Enabled || st.AlertsTotal != 3 || st.Received != 3 {
		t.Fatalf("stats = %+v, want enabled=true alerts_total=3 received=3", st)
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestAlertsHTTPModeFilter HTTP 层默认透传 mode/run_id 过滤：
//   - /api/alerts?mode=static 只回 static；
//   - /api/alerts?run_id=... 只回该 run；
//   - 非法 mode 一律当空（不过滤），绝不 400。
func TestAlertsHTTPModeFilter(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	svc := New(Config{Capacity: 100})
	svc.Start(bus, "detect.feature")
	t.Cleanup(svc.Stop)

	if err := bus.Publish("detect.feature", alertJSONMeta("live-run", ModeLive, "run-live")); err != nil {
		t.Fatalf("Publish live: %v", err)
	}
	if err := bus.Publish("detect.feature", alertJSONMeta("static-run", ModeStatic, "run-static")); err != nil {
		t.Fatalf("Publish static: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return svc.Stats().AlertsTotal == 2 })

	ts := newHTTPTestServer(t, svc)

	var static Page
	getJSON(t, ts.URL+"/api/alerts?mode=static", &static)
	if static.Total != 1 || len(static.Items) != 1 || static.Items[0].Mode != ModeStatic {
		t.Fatalf("mode=static => total=%d items=%+v, want 仅 1 条 static", static.Total, static.Items)
	}

	var byRun Page
	getJSON(t, ts.URL+"/api/alerts?run_id=run-live", &byRun)
	if byRun.Total != 1 || byRun.Items[0].RunID != "run-live" {
		t.Fatalf("run_id=run-live => total=%d items=%+v, want 仅 run-live", byRun.Total, byRun.Items)
	}

	// 非法 mode 当空 ⇒ 不过滤，返回全部（且必须 200，不是 400）。
	var all Page
	getJSON(t, ts.URL+"/api/alerts?mode=bogus", &all)
	if all.Total != 2 {
		t.Fatalf("mode=bogus total = %d, want 2（非法值一律当空不过滤）", all.Total)
	}
}

// alertJSONCapture 造一条带 mode/run_id/capture_id 归属的合法告警 JSON。
func alertJSONCapture(ruleID, mode, runID, captureID string) []byte {
	return []byte(`{"rule_id":"` + ruleID + `","name":"` + ruleID + ` name",` +
		`"severity":"high","weight":80,"time":"2024-01-02T03:04:05Z",` +
		`"mode":"` + mode + `","run_id":"` + runID + `",` +
		`"capture_id":"` + captureID + `"}`)
}

// TestAlertsHTTPCaptureIDFilter HTTP 层透传 capture_id：
//   - /api/alerts?capture_id=cap-A 只回 A，且 total 是过滤后的条数；
//   - 与 mode 组合仍精确；
//   - 缺省/未知 capture_id 不报 400（未知当空 ⇒ 全部）。
func TestAlertsHTTPCaptureIDFilter(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	svc := New(Config{Capacity: 100})
	svc.Start(bus, "detect.feature")
	t.Cleanup(svc.Stop)

	pubs := []struct{ rule, mode, run, capture string }{
		{"a1", ModeStatic, "run-a", "cap-A"},
		{"b1", ModeStatic, "run-b", "cap-B"},
		{"a2", ModeStatic, "run-a", "cap-A"},
	}
	for _, p := range pubs {
		if err := bus.Publish("detect.feature", alertJSONCapture(p.rule, p.mode, p.run, p.capture)); err != nil {
			t.Fatalf("Publish %s: %v", p.rule, err)
		}
	}
	waitFor(t, 2*time.Second, func() bool { return svc.Stats().AlertsTotal == len(pubs) })

	ts := newHTTPTestServer(t, svc)

	var byCapture Page
	getJSON(t, ts.URL+"/api/alerts?capture_id=cap-A", &byCapture)
	if byCapture.Total != 2 {
		t.Fatalf("capture_id=cap-A total = %d, want 2（total 应是过滤后条数）", byCapture.Total)
	}
	if len(byCapture.Items) != 2 {
		t.Fatalf("capture_id=cap-A items = %d, want 2", len(byCapture.Items))
	}
	for _, a := range byCapture.Items {
		if a.CaptureID != "cap-A" {
			t.Fatalf("capture_id=cap-A 返回了 %q 的告警", a.CaptureID)
		}
	}

	var combined Page
	getJSON(t, ts.URL+"/api/alerts?mode=static&capture_id=cap-A", &combined)
	if combined.Total != 2 || len(combined.Items) != 2 {
		t.Fatalf("mode=static&capture_id=cap-A => total=%d items=%d, want 2/2", combined.Total, len(combined.Items))
	}

	// 缺省 capture_id 不过滤 ⇒ 返回全部（200，不 400）。
	var all Page
	getJSON(t, ts.URL+"/api/alerts", &all)
	if all.Total != 3 {
		t.Fatalf("无 capture_id total = %d, want 3（不过滤）", all.Total)
	}

	// 未知 capture_id 属合法过滤值 ⇒ 空结果（200，不 400）。
	var unknown Page
	getJSON(t, ts.URL+"/api/alerts?capture_id=cap-X", &unknown)
	if unknown.Total != 0 || len(unknown.Items) != 0 {
		t.Fatalf("未知 capture_id => total=%d items=%d, want 0/0", unknown.Total, len(unknown.Items))
	}
}
