package capture

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"flow-monitoring/pkg/plugin"
)

// staticTestConfig 构造“只做静态分析”的配置：replay_file 为空，
// DataDir 指向 testdata 根目录，便于用 CaptureRecord.FilePath 拼绝对路径。
func staticTestConfig(t *testing.T) plugin.ConfigSnapshot {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"detect": map[string]string{
			"rules_dir":   filepath.Join("..", "..", "..", "rules"),
			"replay_file": "",
		},
	})
	if err != nil {
		t.Fatalf("构造测试配置失败: %v", err)
	}
	return plugin.ConfigSnapshot{
		Raw:     string(raw),
		DataDir: filepath.Join("..", "..", "..", "testdata"),
	}
}

// staticTestCapture 返回测试用抓包记录（相对 DataDir 的 FilePath）。
func staticTestCapture() plugin.CaptureRecord {
	return plugin.CaptureRecord{
		ID:       "cap-sqli",
		Name:     "sqli.pcapng",
		Format:   "pcapng",
		FilePath: filepath.Join("attacks", "sqli.pcapng"),
	}
}

// newStaticModule 启动一个只等待静态任务的 capture 模块。
func newStaticModule(t *testing.T, maxRuns int) (*captureModule, *fakeHost, http.Handler) {
	t.Helper()
	cfg := staticTestConfig(t)
	host := newFakeHost(cfg)
	host.captures = map[string]plugin.CaptureRecord{
		"cap-sqli": staticTestCapture(),
	}
	m := &captureModule{}
	if maxRuns > 0 {
		m.maxRuns = maxRuns
	}
	if err := m.start(host, cfg); err != nil {
		t.Fatalf("start 失败: %v", err)
	}
	t.Cleanup(func() { _ = m.stop() })
	return m, host, m.handler()
}

func createStaticRun(t *testing.T, h http.Handler, captureID string) *httptest.ResponseRecorder {
	t.Helper()
	body := strings.NewReader(`{"mode":"static","capture_id":"` + captureID + `"}`)
	req := httptest.NewRequest(http.MethodPost, httpBase+"/runs", body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeRunView(t *testing.T, rec *httptest.ResponseRecorder) runView {
	t.Helper()
	var v runView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("响应不是合法 Run JSON: %v（body=%s）", err, rec.Body.String())
	}
	return v
}

func waitRunFinished(t *testing.T, m *captureModule, id string) runView {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if v, ok := m.getRun(id); ok && v.State != runStateRunning {
			return v
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("Run %s 未在超时内完成", id)
	return runView{}
}

// TestStaticRunsConcurrentIsolated 两个 static Run 并发分析同一文件：
// 各自产出 3 条告警、run_id 不同、mode=static，且计数互不串流。
func TestStaticRunsConcurrentIsolated(t *testing.T) {
	m, host, h := newStaticModule(t, 0)

	var wg sync.WaitGroup
	ids := make([]string, 2)
	codes := make([]int, 2)
	bodies := make([]string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := createStaticRun(t, h, "cap-sqli")
			codes[i] = rec.Code
			bodies[i] = rec.Body.String()
			if rec.Code == http.StatusCreated {
				var v runView
				if err := json.Unmarshal(rec.Body.Bytes(), &v); err == nil {
					ids[i] = v.ID
				}
			}
		}(i)
	}
	wg.Wait()

	for i := 0; i < 2; i++ {
		if codes[i] != http.StatusCreated {
			t.Fatalf("第 %d 个 POST 返回 %d，期望 201（body=%s）", i, codes[i], bodies[i])
		}
	}
	if ids[0] == "" || ids[1] == "" {
		t.Fatalf("未解析到 run id: %v", ids)
	}
	if ids[0] == ids[1] {
		t.Fatalf("两个并发 Run 的 run_id 相同: %s", ids[0])
	}

	v0 := waitRunFinished(t, m, ids[0])
	v1 := waitRunFinished(t, m, ids[1])
	for i, v := range []runView{v0, v1} {
		if v.State != runStateDone {
			t.Errorf("Run[%d] state = %q，期望 done", i, v.State)
		}
		if v.Packets != 1 {
			t.Errorf("Run[%d] packets = %d，期望 1", i, v.Packets)
		}
		if v.Alerts != 3 {
			t.Errorf("Run[%d] alerts = %d，期望 3", i, v.Alerts)
		}
		if v.Mode != modeStatic {
			t.Errorf("Run[%d] mode = %q，期望 static", i, v.Mode)
		}
	}

	pubs, logs := host.snapshot()
	byRun := map[string][]map[string]any{}
	for _, p := range pubs {
		if p.topic != topicDetectFeature {
			t.Errorf("event topic = %q，期望 %q", p.topic, topicDetectFeature)
		}
		var obj map[string]any
		if err := json.Unmarshal(p.data, &obj); err != nil {
			t.Fatalf("event payload 不是合法 JSON: %v（payload=%s）", err, p.data)
		}
		rid, _ := obj["run_id"].(string)
		byRun[rid] = append(byRun[rid], obj)
	}

	for _, id := range ids {
		got := byRun[id]
		if len(got) != 3 {
			t.Fatalf("run %s 的告警数 = %d，期望 3（日志：%v）", id, len(got), logs)
		}
		for _, obj := range got {
			if mode, _ := obj["mode"].(string); mode != modeStatic {
				t.Errorf("run %s 的告警 mode = %q，期望 static", id, mode)
			}
			if cid, _ := obj["capture_id"].(string); cid != "cap-sqli" {
				t.Errorf("run %s 的告警 capture_id = %q，期望 cap-sqli", id, cid)
			}
		}
	}
	// 确认没有第三条 run_id（告警不会串到别的归属）。
	if len(byRun) != 2 {
		t.Errorf("告警归属的 run_id 数 = %d，期望 2（%v）", len(byRun), byRun)
	}
}

// TestListRunsEmptyItemsIsArray 无 Run 时 GET /runs 的 items 必须是 []。
func TestListRunsEmptyItemsIsArray(t *testing.T) {
	_, _, h := newStaticModule(t, 0)

	req := httptest.NewRequest(http.MethodGet, httpBase+"/runs", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /runs 返回 %d，期望 200", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"items":[]`) {
		t.Fatalf("items 不是空数组（疑似 null）: %s", body)
	}
	var resp runsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if resp.Items == nil {
		t.Fatal("items 解码后为 nil，期望空切片")
	}
	if resp.Total != 0 {
		t.Errorf("total = %d，期望 0", resp.Total)
	}
}

// TestCreateRunRejectsWhenAtCapacity 并发名额满（maxRuns 个 running）后新建返回 409。
//
// ★ 必须用阻塞数据源保证前几个 Run 仍在 running：
// 通过 HTTP 建 Run 会读真文件、瞬间结束，而已结束的 Run **不占并发名额**
// （那是另一个语义，见 TestFinishedRunsDoNotConsumeCapacity）。
// 早期版本用 HTTP 建 Run 来测容量，结果依赖时序 —— 本机绿、容器里红（flaky）。
func TestCreateRunRejectsWhenAtCapacity(t *testing.T) {
	m, _, h := newStaticModule(t, 1)

	// 直接建一个"永远在跑"的 Run，稳定占住唯一名额。
	blocking := &blockingSource{unblock: make(chan struct{})}
	if _, err := m.addRun("static", "test:blocking", "", blocking); err != nil {
		t.Fatalf("建第一个 Run 失败: %v", err)
	}
	defer close(blocking.unblock)

	rec := createStaticRun(t, h, "cap-sqli")
	if rec.Code != http.StatusConflict {
		t.Fatalf("并发名额满时 POST 返回 %d，期望 409（body=%s）", rec.Code, rec.Body.String())
	}
}

// TestCreateRunValidation 覆盖 400（缺 capture_id）与 404（未知 capture_id）。
func TestCreateRunValidation(t *testing.T) {
	_, _, h := newStaticModule(t, 0)

	rec := createStaticRun(t, h, "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("空 capture_id 返回 %d，期望 400", rec.Code)
	}

	rec = createStaticRun(t, h, "cap-missing")
	if rec.Code != http.StatusNotFound {
		t.Errorf("未知 capture_id 返回 %d，期望 404", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, httpBase+"/runs/does-not-exist", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET 未知 run 返回 %d，期望 404", rec.Code)
	}
}

// blockingSource 一直阻塞到 ctx 取消，用于验证 DELETE 能停掉正在跑的 Run。
type blockingSource struct {
	unblock chan struct{}
}

func (s *blockingSource) Next(ctx context.Context) (Frame, error) {
	select {
	case <-ctx.Done():
		return Frame{}, ctx.Err()
	case <-s.unblock:
		return Frame{}, io.EOF
	}
}

func (s *blockingSource) Describe() string { return "test:blocking" }
func (s *blockingSource) Close() error     { return nil }

// TestDeleteRunningRunStopsAndIsIdempotent DELETE 正在跑的 Run ⇒ done；
// 再删一次不报错。
func TestDeleteRunningRunStopsAndIsIdempotent(t *testing.T) {
	m, _, h := newStaticModule(t, 0)

	run, err := m.addRun(modeStatic, "test:blocking", "cap-blocking", &blockingSource{unblock: make(chan struct{})})
	if err != nil {
		t.Fatalf("addRun 失败: %v", err)
	}
	if v, ok := m.getRun(run.ID); !ok || v.State != runStateRunning {
		t.Fatalf("新 Run 状态 = %+v, ok=%v，期望 running", v, ok)
	}

	del := httptest.NewRequest(http.MethodDelete, httpBase+"/runs/"+run.ID, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, del)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE 返回 %d，期望 200（body=%s）", rec.Code, rec.Body.String())
	}
	if v := decodeRunView(t, rec); v.State != runStateDone {
		t.Fatalf("DELETE 后 state = %q，期望 done", v.State)
	}

	// 幂等：重复删除仍 200，状态仍 done。
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodDelete, httpBase+"/runs/"+run.ID, nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("第二次 DELETE 返回 %d，期望 200（body=%s）", rec2.Code, rec2.Body.String())
	}
	if v := decodeRunView(t, rec2); v.State != runStateDone {
		t.Fatalf("第二次 DELETE 后 state = %q，期望 done", v.State)
	}
}

// TestFinishedRunsDoNotConsumeCapacity 已结束的 Run 不占用并发名额。
//
// ★ 这是一个真实缺陷的回归测试（16-3 验收时实测暴露）：
// 早期实现用 len(m.runs) 判断上限，而 done 的 Run 为了"可查询历史"会保留在表里，
// 结果是「分析 maxRuns 次之后，就再也建不了新 Run，除非重启进程」。
// 正确语义：并发上限只统计 state==running；已结束的另外用 keepFinishedRuns 控制保留量。
func TestFinishedRunsDoNotConsumeCapacity(t *testing.T) {
	const maxRuns = 2
	m, _, h := newStaticModule(t, maxRuns)
	captureID := staticTestCapture().ID

	// 连续建 5 个、每个都等它跑完。若 done 占名额，第 3 个就会被 409 拒绝。
	for i := 1; i <= 5; i++ {
		rec := createStaticRun(t, h, captureID)
		if rec.Code != http.StatusCreated {
			t.Fatalf("第 %d 个 Run 创建失败：code=%d body=%s（已结束的 Run 不该占并发名额）",
				i, rec.Code, rec.Body.String())
		}
		waitRunFinished(t, m, decodeRunView(t, rec).ID)
	}

	items := m.listRuns()
	if len(items) != 5 {
		t.Fatalf("runs 表中 %d 条，期望 5（已结束的 Run 应保留供查询）", len(items))
	}
	for _, it := range items {
		if it.State == runStateRunning {
			t.Fatalf("Run %s 仍为 running，期望全部结束", it.ID)
		}
	}
}
