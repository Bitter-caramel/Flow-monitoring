package alerting

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/eventbus"
)

// repoRoot 从测试文件位置向上找到含 go.mod 的仓库根目录。
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 失败")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("向上未找到 go.mod")
		}
		dir = parent
	}
}

// alertJSON 造一条与 capture featureEvent 形状一致的合法告警 JSON。
func alertJSON(ruleID string) []byte {
	return []byte(`{"rule_id":"` + ruleID + `","name":"` + ruleID + ` name",` +
		`"severity":"high","weight":80,"time":"2024-01-02T03:04:05Z",` +
		`"src_ip":"10.0.0.1","src_port":1234,"dst_ip":"10.0.0.2","dst_port":80,` +
		`"proto":"HTTP","stream_id":7,"buffer":"payload","offset":3,"snippet":"abc"}`)
}

// waitFor 轮询等待异步消费完成（避免测试里 sleep 固定时长）。
func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("等待条件超时（%s）", d)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestServiceSubscribesAndQueries 真 eventbus 投 3 条合法 JSON ⇒ Query 3 条，id 1,2,3。
func TestServiceSubscribesAndQueries(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	svc := New(Config{Capacity: 100})
	svc.Start(bus, "detect.feature")
	defer svc.Stop()

	for i := 1; i <= 3; i++ {
		if err := bus.Publish("detect.feature", alertJSON(fmt.Sprintf("r%d", i))); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}
	waitFor(t, 2*time.Second, func() bool {
		st := svc.Stats()
		return st.Received == 3 && st.AlertsTotal == 3
	})

	p := svc.Query(1, DefaultPageSize, 0, Filter{})
	if p.Total != 3 || len(p.Items) != 3 {
		t.Fatalf("total=%d items=%d, want 3/3", p.Total, len(p.Items))
	}
	for i, a := range p.Items {
		if a.ID != uint64(i+1) {
			t.Errorf("items[%d].ID = %d, want %d（必须按 id 升序）", i, a.ID, i+1)
		}
	}
	// 字段要从 JSON 正确解出（不是 detect.Alert，而是宿主 DTO）。
	first := p.Items[0]
	if first.RuleID != "r1" || first.SrcIP != "10.0.0.1" || first.SrcPort != 1234 ||
		first.DstPort != 80 || first.Proto != "HTTP" || first.StreamID != 7 ||
		first.Buffer != "payload" || first.Offset != 3 || first.Snippet != "abc" {
		t.Errorf("items[0] 字段解码错误: %+v", first)
	}
	if first.Time != "2024-01-02T03:04:05Z" {
		t.Errorf("items[0].Time = %q, want RFC3339 原样透传", first.Time)
	}

	st := svc.Stats()
	if !st.Enabled || st.Capacity != 100 || st.DecodeErrors != 0 || st.Dropped != 0 {
		t.Errorf("stats = %+v, want enabled=true capacity=100 decode_errors=0 dropped=0", st)
	}
}

// TestServiceDecodeErrorCounted 非法 JSON 计入 decode_errors，且不影响其它告警。
func TestServiceDecodeErrorCounted(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	svc := New(Config{Capacity: 100})
	svc.Start(bus, "detect.feature")
	defer svc.Stop()

	if err := bus.Publish("detect.feature", []byte("this-is-not-json")); err != nil {
		t.Fatalf("Publish 非法: %v", err)
	}
	if err := bus.Publish("detect.feature", alertJSON("ok")); err != nil {
		t.Fatalf("Publish 合法: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return svc.Stats().Received == 2 })

	st := svc.Stats()
	if st.DecodeErrors != 1 {
		t.Errorf("decode_errors = %d, want 1", st.DecodeErrors)
	}
	if st.LastError == "" {
		t.Error("last_error 为空，want 非空（解析失败不许静默丢弃）")
	}
	if st.AlertsTotal != 1 {
		t.Errorf("alerts_total = %d, want 1（非法 JSON 不应影响正常告警）", st.AlertsTotal)
	}
	if p := svc.Query(1, 10, 0, Filter{}); p.Total != 1 || p.Items[0].RuleID != "ok" {
		t.Errorf("query = %+v, want 仅 ok 一条", p)
	}
}

// TestServiceHandlesRawMessagePayload 跨进程桥接（Bridge.Publish）用 json.RawMessage，
// 必须能解码，否则真实链路会全挂在类型断言上。
func TestServiceHandlesRawMessagePayload(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	svc := New(Config{Capacity: 10})
	svc.Start(bus, "detect.feature")
	defer svc.Stop()

	if err := bus.Publish("detect.feature", json.RawMessage(alertJSON("raw"))); err != nil {
		t.Fatalf("Publish RawMessage: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return svc.Stats().AlertsTotal == 1 })

	if p := svc.Query(1, 10, 0, Filter{}); p.Total != 1 || p.Items[0].RuleID != "raw" {
		t.Fatalf("query = %+v, want raw 一条", p)
	}
}

// TestServiceNonBytePayloadIsDecodeError 非字节载荷计入 decode_errors（不静默跳过）。
func TestServiceNonBytePayloadIsDecodeError(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	svc := New(Config{Capacity: 10})
	svc.Start(bus, "detect.feature")
	defer svc.Stop()

	if err := bus.Publish("detect.feature", 42); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return svc.Stats().Received == 1 })

	if st := svc.Stats(); st.DecodeErrors != 1 || st.AlertsTotal != 0 {
		t.Fatalf("stats = %+v, want decode_errors=1 alerts_total=0", st)
	}
}

// TestServiceStartIdempotentAndStopUnsubscribes 重复 Start 只订阅一次；Stop 后订阅回收。
func TestServiceStartIdempotentAndStopUnsubscribes(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	svc := New(Config{Capacity: 10})
	svc.Start(bus, "detect.feature")
	svc.Start(bus, "detect.feature") // no-op
	if got := bus.SubscriberCount(); got != 1 {
		t.Fatalf("SubscriberCount = %d, want 1（重复 Start 不应重复订阅）", got)
	}

	svc.Stop()
	svc.Stop() // 幂等
	if got := bus.SubscriberCount(); got != 0 {
		t.Fatalf("Stop 后 SubscriberCount = %d, want 0（订阅必须成对退订）", got)
	}
}

// TestServiceStartNoop nil bus / 空 topic 不 panic、不启动。
func TestServiceStartNoop(t *testing.T) {
	svc := New(Config{Capacity: 10})
	svc.Start(nil, "detect.feature")
	svc.Start(eventbus.New(), "")
	if st := svc.Stats(); st.Enabled {
		t.Errorf("enabled = true, want false（未订阅成功）")
	}
	svc.Stop()
}

// alertJSONMeta 造一条带 run_id/mode 归属的合法告警 JSON（字段与 featureEvent 对齐）。
func alertJSONMeta(ruleID, mode, runID string) []byte {
	return []byte(`{"rule_id":"` + ruleID + `","name":"` + ruleID + ` name",` +
		`"severity":"high","weight":80,"time":"2024-01-02T03:04:05Z",` +
		`"mode":"` + mode + `","run_id":"` + runID + `"}`)
}

// TestServiceQueryFilter 服务层 Query 的过滤：Filter{} 返回全部，mode/run_id 精确筛选。
func TestServiceQueryFilter(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	svc := New(Config{Capacity: 100})
	svc.Start(bus, "detect.feature")
	defer svc.Stop()

	pubs := []struct{ mode, run string }{
		{ModeLive, "run-1"},
		{ModeLive, "run-1"},
		{ModeStatic, "run-2"},
	}
	for i, p := range pubs {
		if err := bus.Publish("detect.feature", alertJSONMeta(fmt.Sprintf("r%d", i), p.mode, p.run)); err != nil {
			t.Fatalf("Publish #%d: %v", i, err)
		}
	}
	waitFor(t, 2*time.Second, func() bool { return svc.Stats().AlertsTotal == len(pubs) })

	if p := svc.Query(1, MaxPageSize, 0, Filter{}); p.Total != 3 {
		t.Errorf("Filter{} total = %d, want 3（空过滤返回全部）", p.Total)
	}
	if p := svc.Query(1, MaxPageSize, 0, Filter{Mode: ModeStatic}); p.Total != 1 || p.Items[0].Mode != ModeStatic {
		t.Errorf("mode=static => %+v, want 仅 1 条 static", p)
	}
	if p := svc.Query(1, MaxPageSize, 0, Filter{RunID: "run-1"}); p.Total != 2 {
		t.Errorf("run_id=run-1 total = %d, want 2", p.Total)
	}
	if p := svc.Query(1, MaxPageSize, 0, Filter{Mode: ModeLive, RunID: "run-2"}); p.Total != 0 {
		t.Errorf("mode=live&run_id=run-2 total = %d, want 0（组合条件无命中）", p.Total)
	}
}

// TestServiceStatsByModeAndRun Stats().ByMode / ByRun 的计数与入库告警一致。
func TestServiceStatsByModeAndRun(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	svc := New(Config{Capacity: 100})
	svc.Start(bus, "detect.feature")
	defer svc.Stop()

	pubs := []struct{ mode, run string }{
		{ModeLive, "run-1"},
		{ModeLive, "run-2"},
		{ModeStatic, "run-3"},
		{ModeLive, "run-1"},
	}
	for i, p := range pubs {
		if err := bus.Publish("detect.feature", alertJSONMeta(fmt.Sprintf("r%d", i), p.mode, p.run)); err != nil {
			t.Fatalf("Publish #%d: %v", i, err)
		}
	}
	waitFor(t, 2*time.Second, func() bool { return svc.Stats().AlertsTotal == len(pubs) })

	st := svc.Stats()
	if st.ByMode[ModeLive] != 3 || st.ByMode[ModeStatic] != 1 {
		t.Errorf("ByMode = %v, want live=3 static=1", st.ByMode)
	}
	if st.ByRun["run-1"] != 2 || st.ByRun["run-2"] != 1 || st.ByRun["run-3"] != 1 {
		t.Errorf("ByRun = %v, want run-1=2 run-2=1 run-3=1", st.ByRun)
	}
}
