package capture

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"flow-monitoring/internal/hotpath"
	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/modules/detect"
	"flow-monitoring/pkg/plugin"
)

// publishedEvent 记录一次 Publish 调用。
type publishedEvent struct {
	topic string
	data  []byte
}

// fakeHost 是 plugin.Host 的最小桩：记录 Publish/Log，并可从 captures 表
// 返回固定的抓包记录（静态分析用例需要 CaptureGet 命中）。
type fakeHost struct {
	cfg      plugin.ConfigSnapshot
	captures map[string]plugin.CaptureRecord

	mu        sync.Mutex
	published []publishedEvent
	logs      []string

	done     chan struct{}
	doneOnce sync.Once
}

var _ plugin.Host = (*fakeHost)(nil)

func newFakeHost(cfg plugin.ConfigSnapshot) *fakeHost {
	return &fakeHost{cfg: cfg, done: make(chan struct{})}
}

func (h *fakeHost) Config() plugin.ConfigSnapshot { return h.cfg }

func (h *fakeHost) Log(level, msg string) {
	h.mu.Lock()
	h.logs = append(h.logs, level+"|"+msg)
	h.mu.Unlock()
	if strings.Contains(msg, "capture: replay finished") {
		h.doneOnce.Do(func() { close(h.done) })
	}
}

func (h *fakeHost) Publish(topic string, data []byte) error {
	cp := append([]byte(nil), data...)
	h.mu.Lock()
	h.published = append(h.published, publishedEvent{topic: topic, data: cp})
	h.mu.Unlock()
	return nil
}

func (h *fakeHost) Poll(string, uint64, int) []plugin.EventRecord { return nil }

func (h *fakeHost) RegisterHTTP(string, string, string) error { return nil }

func (h *fakeHost) RegisterService(plugin.ServiceRef) error { return nil }

func (h *fakeHost) LookupService(string) (plugin.ServiceRef, bool) {
	return plugin.ServiceRef{}, false
}

func (h *fakeHost) UnregisterService(string) error { return nil }

func (h *fakeHost) CaptureCreate(plugin.CaptureRecord) error { return nil }

func (h *fakeHost) CaptureGet(id string) (plugin.CaptureRecord, bool) {
	rec, ok := h.captures[id]
	return rec, ok
}

func (h *fakeHost) CaptureList(plugin.Page) plugin.CapturePage { return plugin.CapturePage{} }

func (h *fakeHost) CaptureDelete(string) error { return nil }

func (h *fakeHost) PacketSaveBatch(string, []plugin.PacketRecord) error { return nil }

func (h *fakeHost) PacketList(string, plugin.Page) plugin.PacketPage {
	return plugin.PacketPage{}
}

func (h *fakeHost) PacketCount(string) int { return 0 }

func (h *fakeHost) PacketDelete(string) error { return nil }

func (h *fakeHost) waitDone(t *testing.T) {
	t.Helper()
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		t.Fatal("等待“capture: replay finished”日志超时")
	}
}

func (h *fakeHost) snapshot() ([]publishedEvent, []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	pubs := append([]publishedEvent(nil), h.published...)
	logs := append([]string(nil), h.logs...)
	return pubs, logs
}

// testSnapshot 构造只含 detect 私有段的宿主配置快照。
func testSnapshot(t *testing.T, replayName string) plugin.ConfigSnapshot {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"detect": map[string]string{
			"rules_dir":   filepath.Join("..", "..", "..", "rules"),
			"replay_file": filepath.Join("..", "..", "..", "testdata", "attacks", replayName),
		},
	})
	if err != nil {
		t.Fatalf("构造测试配置失败: %v", err)
	}
	return plugin.ConfigSnapshot{Raw: string(raw)}
}

// TestModulePublishesSQLiAlerts 用 sqli 样本跑完整回放：
// 每个告警 → detect.feature，且 payload 带 rule_id。
func TestModulePublishesSQLiAlerts(t *testing.T) {
	host := newFakeHost(testSnapshot(t, "sqli.pcapng"))
	m := &captureModule{}
	if err := m.start(host, host.cfg); err != nil {
		t.Fatalf("start 失败: %v", err)
	}
	defer m.stop()

	host.waitDone(t)

	pubs, logs := host.snapshot()
	if got, want := len(pubs), 3; got != want {
		t.Fatalf("Publish 调用次数 = %d，期望 %d（日志：%v）", got, want, logs)
	}
	for i, p := range pubs {
		if p.topic != topicDetectFeature {
			t.Errorf("Publish[%d] topic = %q，期望 %q", i, p.topic, topicDetectFeature)
		}
		var obj map[string]any
		if err := json.Unmarshal(p.data, &obj); err != nil {
			t.Fatalf("Publish[%d] payload 不是合法 JSON: %v（payload=%s）", i, err, p.data)
		}
		ruleID, ok := obj["rule_id"]
		if !ok || ruleID == "" {
			t.Errorf("Publish[%d] payload 缺少 rule_id: %s", i, p.data)
		}
		t.Logf("publish[%d] topic=%s payload=%s", i, p.topic, p.data)
	}

	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "capture: replay finished, packets=1 alerts=3 publish_errs=0") {
		t.Errorf("结束日志不符合预期，实际日志：\n%s", joined)
	}
	if st := m.health(); !st.Healthy {
		t.Errorf("回放正常结束后 Health = %+v，期望 healthy", st)
	}
}

// TestModuleNormalNoAlerts 用 normal 样本验证零命中时 Publish 不调用。
func TestModuleNormalNoAlerts(t *testing.T) {
	host := newFakeHost(testSnapshot(t, "normal.pcapng"))
	m := &captureModule{}
	if err := m.start(host, host.cfg); err != nil {
		t.Fatalf("start 失败: %v", err)
	}
	defer m.stop()

	host.waitDone(t)

	pubs, logs := host.snapshot()
	if got := len(pubs); got != 0 {
		t.Fatalf("Publish 调用次数 = %d，期望 0（日志：%v）", got, logs)
	}
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "capture: replay finished, packets=2 alerts=0 publish_errs=0") {
		t.Errorf("结束日志不符合预期，实际日志：\n%s", joined)
	}
}

// sliceSource 是测试用数据源：按切片返回固定帧，耗尽后 io.EOF。
type sliceSource struct {
	frames []Frame
	idx    int
}

func (s *sliceSource) Next(ctx context.Context) (Frame, error) {
	if err := ctx.Err(); err != nil {
		return Frame{}, err
	}
	if s.idx >= len(s.frames) {
		return Frame{}, io.EOF
	}
	f := s.frames[s.idx]
	s.idx++
	return f, nil
}

func (s *sliceSource) Describe() string { return "test:slice" }

func (s *sliceSource) Close() error { return nil }

// TestModuleRecoversPerPacketPanic 验证单个包 Process panic 后主循环继续并正常结束。
func TestModuleRecoversPerPacketPanic(t *testing.T) {
	src := &sliceSource{frames: []Frame{
		{TS: time.Now(), LinkType: 1},
		{TS: time.Now(), LinkType: 1},
	}}
	host := newFakeHost(testSnapshot(t, "sqli.pcapng"))
	m := &captureModule{
		newSource: func(string) (Source, error) { return src, nil },
		process: func(hp *hotpath.Hotpath, p *datamodel.Packet) []detect.Alert {
			if p.No == 1 {
				panic("boom")
			}
			return hp.Process(p)
		},
	}
	if err := m.start(host, host.cfg); err != nil {
		t.Fatalf("start 失败: %v", err)
	}
	defer m.stop()

	host.waitDone(t)

	pubs, logs := host.snapshot()
	if got := len(pubs); got != 0 {
		t.Fatalf("Publish 调用次数 = %d，期望 0（坏包不应产出告警）", got)
	}
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "panic recovered") {
		t.Errorf("缺少 panic 恢复日志，实际日志：\n%s", joined)
	}
	if !strings.Contains(joined, "capture: replay finished, packets=2 alerts=0 publish_errs=0") {
		t.Errorf("主循环未正常结束，实际日志：\n%s", joined)
	}
	if got := m.panicCount; got != 1 {
		t.Errorf("panicCount = %d，期望 1", got)
	}
	if st := m.health(); !st.Healthy {
		t.Errorf("回放正常结束后 Health = %+v，期望 healthy", st)
	}
}

// TestModuleHealthOnBadRulesDir 验证规则目录加载失败时 OnHealth 返回不健康。
func TestModuleHealthOnBadRulesDir(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"detect": map[string]string{
			"rules_dir":   filepath.Join("..", "..", "..", "testdata", "does-not-exist"),
			"replay_file": filepath.Join("..", "..", "..", "testdata", "attacks", "sqli.pcapng"),
		},
	})
	if err != nil {
		t.Fatalf("构造测试配置失败: %v", err)
	}
	host := newFakeHost(plugin.ConfigSnapshot{Raw: string(raw)})
	m := &captureModule{}
	if err := m.start(host, host.cfg); err != nil {
		t.Fatalf("start 不应返回错误（加载失败由 Health 上报）: %v", err)
	}
	defer m.stop()

	st := m.health()
	if st.Healthy {
		t.Fatalf("Health = %+v，期望不健康", st)
	}
	if st.Message == "" {
		t.Error("不健康状态应带原因")
	}
}

// TestModulePublishesRunIDAndMode featureEvent 载荷必须带 run_id 与 mode=live，
// 供宿主按分析任务归属过滤（阶段 2 的唯一产出 mode 是 live）。
func TestModulePublishesRunIDAndMode(t *testing.T) {
	host := newFakeHost(testSnapshot(t, "sqli.pcapng"))
	m := &captureModule{}
	if err := m.start(host, host.cfg); err != nil {
		t.Fatalf("start 失败: %v", err)
	}
	defer m.stop()

	host.waitDone(t)

	pubs, logs := host.snapshot()
	if len(pubs) == 0 {
		t.Fatalf("没有任何 Publish（日志：%v）", logs)
	}
	for i, p := range pubs {
		var obj map[string]any
		if err := json.Unmarshal(p.data, &obj); err != nil {
			t.Fatalf("Publish[%d] payload 不是合法 JSON: %v（payload=%s）", i, err, p.data)
		}
		if mode, _ := obj["mode"].(string); mode != modeLive {
			t.Errorf("Publish[%d] mode = %q, want %q（payload=%s）", i, mode, modeLive, p.data)
		}
		runID, _ := obj["run_id"].(string)
		if !strings.HasPrefix(runID, "run-") || len(runID) <= len("run-") {
			t.Errorf("Publish[%d] run_id = %q, want 形如 run-<unixnano>（payload=%s）", i, runID, p.data)
		}
	}
}
