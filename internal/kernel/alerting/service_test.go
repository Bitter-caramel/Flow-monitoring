package alerting

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// task18bRestoreSnakeLine 造一行归档：alert 用宿主 DTO 的 snake_case 键名。
func task18bRestoreSnakeLine(captureID, runID, mode, ruleID, ts string) string {
	return `{"capture_id":"` + captureID + `","run_id":"` + runID + `","mode":"` + mode + `","alert":{` +
		`"rule_id":"` + ruleID + `","name":"n","severity":"high","weight":1,` +
		`"time":"` + ts + `","src_ip":"1.1.1.1","src_port":1,"dst_ip":"2.2.2.2","dst_port":2,` +
		`"proto":"TCP","stream_id":1,"buffer":"payload","offset":0,"snippet":"x"}}`
}

// task18bRestorePascalLine 造一行归档：alert 用 detect.Alert 的 PascalCase 键名
// （data/alerts.jsonl 的真实形状）。
func task18bRestorePascalLine(captureID, runID, mode, ruleID, ts string) string {
	return `{"capture_id":"` + captureID + `","run_id":"` + runID + `","mode":"` + mode + `","alert":{` +
		`"RuleID":"` + ruleID + `","Name":"n","Severity":"high","Weight":1,` +
		`"Time":"` + ts + `","SrcIP":"1.1.1.1","SrcPort":1,"DstIP":"2.2.2.2","DstPort":2,` +
		`"Proto":"TCP","StreamID":1,"Buffer":"payload","Offset":0,"Snippet":"x"}}`
}

// task18bWriteRestoreFile 把若干行写进临时 JSONL（每行以 \n 结尾）。
func task18bWriteRestoreFile(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write restore file: %v", err)
	}
	return path
}

// TestRestoreFromFile 3 条合法（含 PascalCase）+ 1 条坏行 ⇒ 回填 3 条，
// id 1/2/3、按 time 升序、RunID/Mode/CaptureID 保留。
func TestTask18bRestoreFromFile(t *testing.T) {
	path := task18bWriteRestoreFile(t, []string{
		task18bRestoreSnakeLine("cap-3", "run-3", ModeLive, "r3", "2024-01-01T00:00:03Z"),
		"this-is-not-json",
		task18bRestorePascalLine("cap-1", "run-1", ModeStatic, "r1", "2024-01-01T00:00:01Z"),
		task18bRestoreSnakeLine("cap-2", "run-2", ModeLive, "r2", "2024-01-01T00:00:02Z"),
	})

	svc := New(Config{Capacity: 100})
	n, err := svc.RestoreFromFile(path)
	if err != nil {
		t.Fatalf("RestoreFromFile: %v", err)
	}
	if n != 3 {
		t.Fatalf("restored = %d, want 3（坏行应跳过）", n)
	}

	p := svc.Query(1, MaxPageSize, 0, Filter{})
	if p.Total != 3 || len(p.Items) != 3 {
		t.Fatalf("total=%d items=%d, want 3/3", p.Total, len(p.Items))
	}
	// 按 time 升序插入 ⇒ r1/r2/r3，id 1/2/3。
	wantRule := []string{"r1", "r2", "r3"}
	wantCap := []string{"cap-1", "cap-2", "cap-3"}
	wantRun := []string{"run-1", "run-2", "run-3"}
	for i, a := range p.Items {
		if a.ID != uint64(i+1) {
			t.Errorf("items[%d].ID = %d, want %d", i, a.ID, i+1)
		}
		if a.RuleID != wantRule[i] {
			t.Errorf("items[%d].RuleID = %q, want %q", i, a.RuleID, wantRule[i])
		}
		if a.CaptureID != wantCap[i] || a.RunID != wantRun[i] {
			t.Errorf("items[%d] 归属 = %q/%q, want %q/%q",
				i, a.CaptureID, a.RunID, wantCap[i], wantRun[i])
		}
	}
	if p.Items[0].Mode != ModeStatic {
		t.Errorf("items[0].Mode = %q, want %q（PascalCase 行必须解出 mode）", p.Items[0].Mode, ModeStatic)
	}
	// PascalCase 的 alert 字段必须被解出来（不能被 snake_case tag 漏掉）。
	if p.Items[0].Name != "n" || p.Items[0].Severity != "high" || p.Items[0].SrcIP != "1.1.1.1" {
		t.Errorf("items[0] PascalCase 字段解码错误: %+v", p.Items[0])
	}

	st := svc.Stats()
	if st.Restored != 3 {
		t.Errorf("Stats().Restored = %d, want 3", st.Restored)
	}
	if st.Received != 0 {
		t.Errorf("Stats().Received = %d, want 0（回填不计入运行期接收）", st.Received)
	}
	if st.AlertsTotal != 3 {
		t.Errorf("Stats().AlertsTotal = %d, want 3", st.AlertsTotal)
	}

	// 回填后 nextID 必须接上运行期新增的 id（4）。
	rec := svc.ring.add(Alert{RuleID: "live", Time: "2024-01-01T00:00:04Z"})
	if rec.ID != 4 {
		t.Errorf("回填后新增告警 ID = %d, want 4（nextID 必须接上）", rec.ID)
	}
}

// TestRestoreFromFileKeepsLastN 5 行、容量 3 ⇒ 只回填最后 3 条（r3/r4/r5）。
func TestTask18bRestoreKeepsLastN(t *testing.T) {
	lines := make([]string, 0, 5)
	for i := 1; i <= 5; i++ {
		lines = append(lines, task18bRestoreSnakeLine(
			fmt.Sprintf("cap-%d", i), fmt.Sprintf("run-%d", i), ModeLive,
			fmt.Sprintf("r%d", i), fmt.Sprintf("2024-01-01T00:00:0%dZ", i)))
	}
	path := task18bWriteRestoreFile(t, lines)

	svc := New(Config{Capacity: 3})
	n, err := svc.RestoreFromFile(path)
	if err != nil {
		t.Fatalf("RestoreFromFile: %v", err)
	}
	if n != 3 {
		t.Fatalf("restored = %d, want 3（容量截断）", n)
	}
	p := svc.Query(1, MaxPageSize, 0, Filter{})
	if p.Total != 3 {
		t.Fatalf("total = %d, want 3", p.Total)
	}
	want := []string{"r3", "r4", "r5"}
	for i, a := range p.Items {
		if a.RuleID != want[i] {
			t.Errorf("items[%d].RuleID = %q, want %q（只保留最后 3 条）", i, a.RuleID, want[i])
		}
		if a.ID != uint64(i+1) {
			t.Errorf("items[%d].ID = %d, want %d", i, a.ID, i+1)
		}
	}
}

// TestRestoreFromFileMissing 文件不存在 ⇒ (0, nil)（首次运行没有归档）。
func TestTask18bRestoreMissingFile(t *testing.T) {
	svc := New(Config{Capacity: 10})
	n, err := svc.RestoreFromFile(filepath.Join(t.TempDir(), "does-not-exist.jsonl"))
	if err != nil {
		t.Fatalf("RestoreFromFile 缺失文件不应报错: %v", err)
	}
	if n != 0 {
		t.Fatalf("restored = %d, want 0", n)
	}
	if svc.Stats().AlertsTotal != 0 {
		t.Fatalf("AlertsTotal = %d, want 0", svc.Stats().AlertsTotal)
	}
}

// TestRestoreFromFileSkipsBadAlert alert 字段不是对象的坏行被跳过，不影响好行。
func TestTask18bRestoreSkipsBadAlert(t *testing.T) {
	path := task18bWriteRestoreFile(t, []string{
		`{"capture_id":"c1","run_id":"r1","mode":"live","alert":"not-an-object"}`,
		task18bRestoreSnakeLine("c2", "r2", ModeLive, "ok", "2024-01-01T00:00:01Z"),
	})
	svc := New(Config{Capacity: 10})
	n, err := svc.RestoreFromFile(path)
	if err != nil {
		t.Fatalf("RestoreFromFile: %v", err)
	}
	if n != 1 {
		t.Fatalf("restored = %d, want 1", n)
	}
	p := svc.Query(1, MaxPageSize, 0, Filter{})
	if p.Total != 1 || p.Items[0].RuleID != "ok" {
		t.Fatalf("query = %+v, want 1 条 RuleID=ok", p)
	}
}

// TestNewRestoresFromPath New(Config{RestorePath}) 在构造时自动回填（启动接线）。
func TestTask18bNewRestoresFromPath(t *testing.T) {
	path := task18bWriteRestoreFile(t, []string{
		task18bRestoreSnakeLine("c1", "r1", ModeLive, "r1", "2024-01-01T00:00:01Z"),
		task18bRestoreSnakeLine("c2", "r2", ModeStatic, "r2", "2024-01-01T00:00:02Z"),
	})
	svc := New(Config{Capacity: 10, RestorePath: path})
	if st := svc.Stats(); st.Restored != 2 || st.AlertsTotal != 2 {
		t.Fatalf("stats = %+v, want restored=2 alerts_total=2", st)
	}
	if p := svc.Query(1, MaxPageSize, 0, Filter{RunID: "r2"}); p.Total != 1 || p.Items[0].RuleID != "r2" {
		t.Fatalf("按 run_id 过滤失败: %+v", p)
	}
}
