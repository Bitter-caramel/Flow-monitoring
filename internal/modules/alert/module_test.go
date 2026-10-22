package alert

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"flow-monitoring/pkg/plugin"
)

// alertFakeHost 是告警模块测试用的可控宿主桩。
type alertFakeHost struct {
	mu      sync.Mutex
	records map[string][]plugin.EventRecord
	logs    []string
}

var _ plugin.Host = (*alertFakeHost)(nil)

func newAlertFakeHost() *alertFakeHost {
	return &alertFakeHost{records: make(map[string][]plugin.EventRecord)}
}

func (h *alertFakeHost) append(topic string, seq uint64, data []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records[topic] = append(h.records[topic], plugin.EventRecord{
		Topic: topic,
		Seq:   seq,
		Data:  append([]byte(nil), data...),
		Time:  time.Now(),
	})
}

func (h *alertFakeHost) Config() plugin.ConfigSnapshot { return plugin.ConfigSnapshot{} }

func (h *alertFakeHost) Log(level, msg string) {
	h.mu.Lock()
	h.logs = append(h.logs, level+"|"+msg)
	h.mu.Unlock()
}

func (h *alertFakeHost) Publish(string, []byte) error { return nil }

func (h *alertFakeHost) Poll(topic string, since uint64, max int) []plugin.EventRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	if max <= 0 {
		max = 100
	}
	var out []plugin.EventRecord
	for _, ev := range h.records[topic] {
		if ev.Seq > since {
			out = append(out, ev)
			if len(out) >= max {
				break
			}
		}
	}
	return out
}

func (h *alertFakeHost) RegisterHTTP(string, string, string) error { return nil }
func (h *alertFakeHost) RegisterService(plugin.ServiceRef) error   { return nil }
func (h *alertFakeHost) LookupService(string) (plugin.ServiceRef, bool) {
	return plugin.ServiceRef{}, false
}
func (h *alertFakeHost) UnregisterService(string) error           { return nil }
func (h *alertFakeHost) CaptureCreate(plugin.CaptureRecord) error { return nil }
func (h *alertFakeHost) CaptureGet(string) (plugin.CaptureRecord, bool) {
	return plugin.CaptureRecord{}, false
}
func (h *alertFakeHost) CaptureList(plugin.Page) plugin.CapturePage { return plugin.CapturePage{} }
func (h *alertFakeHost) CaptureDelete(string) error                 { return nil }
func (h *alertFakeHost) PacketSaveBatch(string, []plugin.PacketRecord) error {
	return nil
}
func (h *alertFakeHost) PacketList(string, plugin.Page) plugin.PacketPage {
	return plugin.PacketPage{}
}
func (h *alertFakeHost) PacketCount(string) int    { return 0 }
func (h *alertFakeHost) PacketDelete(string) error { return nil }

func (h *alertFakeHost) logText() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.logs, "\n")
}

// waitAlertFor 轮询等待条件成立（名字避开同包 consumer_test.go 里的 waitFor）。
func waitAlertFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("等待 %s 超时", what)
}

// validFeatureJSON 是一条 capture 进程会发布的 detect.feature 载荷。
const validFeatureJSON = `{
  "capture_id": "cap-1",
  "rule_id": "r1",
  "name": "SQL injection",
  "severity": "high",
  "weight": 8,
  "time": "2026-01-02T03:04:05Z",
  "src_ip": "10.0.0.1",
  "src_port": 1234,
  "dst_ip": "10.0.0.2",
  "dst_port": 80,
  "proto": "tcp",
  "stream_id": 1,
  "pkt_no": 7,
  "flow_key": "10.0.0.1:1234->10.0.0.2:80/tcp",
  "buffer": "payload",
  "offset": 3,
  "snippet": "UNION"
}`

// configWithSink 构造 {"alert":{"sink_path":...}} 配置。
func configWithSink(path string) plugin.ConfigSnapshot {
	raw, _ := json.Marshal(map[string]any{"alert": map[string]string{"sink_path": path}})
	return plugin.ConfigSnapshot{Raw: string(raw)}
}

// TestModuleSpec 守住进程模块的清单身份：L2、无 HTTPBase、提供 alert.sink。
func TestModuleSpec(t *testing.T) {
	rt := Module()
	if rt.Spec.ID != "modules.alert" {
		t.Errorf("ID = %q, want modules.alert", rt.Spec.ID)
	}
	if rt.Spec.Layer != plugin.LayerFeature {
		t.Errorf("Layer = %v, want L2", rt.Spec.Layer)
	}
	if rt.Spec.HTTPBase != "" {
		t.Errorf("HTTPBase = %q, want 空（纯事件消费者）", rt.Spec.HTTPBase)
	}
	if len(rt.Spec.Provides) != 1 || rt.Spec.Provides[0] != "alert.sink" {
		t.Errorf("Provides = %v, want [alert.sink]", rt.Spec.Provides)
	}
	if rt.OnStart == nil || rt.OnStop == nil || rt.OnHealth == nil {
		t.Error("OnStart/OnStop/OnHealth 不得为空")
	}
}

// TestModuleWritesValidDetectFeature 守住：合法 detect.feature JSON 落盘一行、Written==1。
func TestModuleWritesValidDetectFeature(t *testing.T) {
	dir := t.TempDir()
	sinkPath := filepath.Join(dir, "alerts.jsonl")

	host := newAlertFakeHost()
	host.append(topicDetectFeature, 1, []byte(validFeatureJSON))

	m := &alertModule{}
	if err := m.start(host, configWithSink(sinkPath)); err != nil {
		t.Fatalf("start 失败: %v", err)
	}
	defer m.stop()

	waitAlertFor(t, "Written==1", func() bool {
		m.mu.Lock()
		c := m.consumer
		m.mu.Unlock()
		return c != nil && c.Written() == 1
	})

	lines := readLines(t, sinkPath)
	if len(lines) != 1 {
		t.Fatalf("告警文件行数 = %d, want 1（内容：%v）", len(lines), lines)
	}
	var ev Event
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatalf("落盘行不是合法 alert.Event: %v（行=%s）", err, lines[0])
	}
	if ev.Alert.RuleID != "r1" {
		t.Errorf("落盘 RuleID = %q, want r1", ev.Alert.RuleID)
	}
	if ev.Alert.PktNo != 7 {
		t.Errorf("落盘 PktNo = %d, want 7", ev.Alert.PktNo)
	}
	if ev.CaptureID != "cap-1" {
		t.Errorf("落盘 CaptureID = %q, want cap-1", ev.CaptureID)
	}

	st := m.health()
	if !st.Healthy {
		t.Fatalf("Health = %+v, want healthy", st)
	}
	if !strings.Contains(st.Message, "已写 1") {
		t.Errorf("Health 消息未报告已写 1：%q", st.Message)
	}
}

// TestModuleInvalidJSONCountsError 守住：非法 JSON 不崩、错误计数增加、不写文件。
func TestModuleInvalidJSONCountsError(t *testing.T) {
	dir := t.TempDir()
	sinkPath := filepath.Join(dir, "alerts.jsonl")

	host := newAlertFakeHost()
	host.append(topicDetectFeature, 1, []byte("this is not json"))

	m := &alertModule{}
	if err := m.start(host, configWithSink(sinkPath)); err != nil {
		t.Fatalf("start 失败: %v", err)
	}
	defer m.stop()

	waitAlertFor(t, "decodeErrs==1", func() bool { return m.decodeErrs.Load() == 1 })

	st := m.health()
	if !st.Healthy {
		t.Fatalf("遇到坏载荷不应让模块不健康，Health = %+v", st)
	}
	if !strings.Contains(st.Message, "错误 1") {
		t.Errorf("Health 消息未报告错误 1：%q", st.Message)
	}
	if lines := readLines(t, sinkPath); len(lines) != 0 {
		t.Errorf("非法载荷不应写文件，实际 %d 行：%v", len(lines), lines)
	}
	// 进程仍然可用：再投一条合法事件，应能继续消费。
	host.append(topicDetectFeature, 2, []byte(validFeatureJSON))
	waitAlertFor(t, "坏载荷后仍能消费", func() bool {
		m.mu.Lock()
		c := m.consumer
		m.mu.Unlock()
		return c != nil && c.Written() == 1
	})
}

// TestModuleHealthBeforeStart 守住：未启动时 Health 不健康且给出原因。
func TestModuleHealthBeforeStart(t *testing.T) {
	m := &alertModule{}
	st := m.health()
	if st.Healthy {
		t.Fatalf("未启动 Health = %+v, want unhealthy", st)
	}
	if !strings.Contains(st.Message, "未启动") {
		t.Errorf("Health 消息 = %q, want 含“未启动”", st.Message)
	}
}

// TestModuleStopIdempotent 守住：重复 OnStop 无副作用、不 panic。
func TestModuleStopIdempotent(t *testing.T) {
	dir := t.TempDir()
	sinkPath := filepath.Join(dir, "alerts.jsonl")

	m := &alertModule{}
	if err := m.start(newAlertFakeHost(), configWithSink(sinkPath)); err != nil {
		t.Fatalf("start 失败: %v", err)
	}
	if err := m.stop(); err != nil {
		t.Fatalf("stop 第一次失败: %v", err)
	}
	if err := m.stop(); err != nil {
		t.Fatalf("stop 第二次失败: %v", err)
	}
}

// TestResolveSinkPath 守住配置解析：嵌套、扁平、缺省三种写法。
func TestResolveSinkPath(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"nested", `{"alert":{"sink_path":"/tmp/a.jsonl"}}`, "/tmp/a.jsonl"},
		{"flat", `{"alert.sink_path":"/tmp/b.jsonl"}`, "/tmp/b.jsonl"},
		{"default", `{}`, defaultSinkPath},
		{"empty", ``, defaultSinkPath},
		{"invalid", `not-json`, defaultSinkPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveSinkPath(plugin.ConfigSnapshot{Raw: tc.raw}); got != tc.want {
				t.Errorf("resolveSinkPath(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// readLines 读文件所有非空行；文件不存在返回 nil。
func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}
