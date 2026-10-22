package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"flow-monitoring/internal/kernel/eventbus"
	"flow-monitoring/internal/modules/common/pollsource"
	"flow-monitoring/internal/modules/detect"
	"flow-monitoring/internal/modules/rule"
	"flow-monitoring/pkg/plugin"
)

const (
	// topicDetectFeature 是检测特征事件主题（capture 进程发布）。
	topicDetectFeature = "detect.feature"
	// defaultSinkPath 是告警 JSONL 的默认落点。
	defaultSinkPath = "data/alerts.jsonl"
	// forwardBuffer 是"解码后转发给 Consumer"的 channel 缓冲。
	forwardBuffer = 256
)

// alertSettings 是本模块从 ConfigSnapshot.Raw 里解析的私有配置段。
type alertSettings struct {
	SinkPath string `json:"sink_path"`
}

// rawConfig 同时兼容 {"alert":{"sink_path":...}} 与 {"alert.sink_path":...} 两种写法。
type rawConfig struct {
	Alert    alertSettings `json:"alert"`
	FlatPath string        `json:"alert.sink_path"`
}

// featureEvent 是 detect.feature 主题的扁平载荷（与 capture 发布的结构一致）。
//
// ★ 这里刻意在本包内重新声明一份 DTO，而不是 import capture 模块：
//
//	消费者只需知道"线上 JSON 的形状"，不依赖生产者实现，才能独立部署/替换。
type featureEvent struct {
	CaptureID string    `json:"capture_id,omitempty"`
	RunID     string    `json:"run_id,omitempty"`
	Mode      string    `json:"mode,omitempty"`
	RuleID    string    `json:"rule_id"`
	Name      string    `json:"name,omitempty"`
	Severity  string    `json:"severity,omitempty"`
	Weight    int       `json:"weight,omitempty"`
	Time      time.Time `json:"time"`
	SrcIP     string    `json:"src_ip,omitempty"`
	SrcPort   uint16    `json:"src_port,omitempty"`
	DstIP     string    `json:"dst_ip,omitempty"`
	DstPort   uint16    `json:"dst_port,omitempty"`
	Proto     string    `json:"proto,omitempty"`
	StreamID  int       `json:"stream_id"`
	PktNo     int       `json:"pkt_no"`
	FlowKey   string    `json:"flow_key,omitempty"`
	Buffer    string    `json:"buffer,omitempty"`
	Offset    int       `json:"offset"`
	Snippet   string    `json:"snippet,omitempty"`
}

// toAlertEvent 把扁平检测特征转成告警落盘结构。
func (f featureEvent) toAlertEvent() Event {
	return Event{
		CaptureID: f.CaptureID,
		Alert: detect.Alert{
			RuleID:   f.RuleID,
			Name:     f.Name,
			Severity: f.Severity,
			Weight:   f.Weight,
			Time:     f.Time,
			SrcIP:    f.SrcIP,
			SrcPort:  f.SrcPort,
			DstIP:    f.DstIP,
			DstPort:  f.DstPort,
			Proto:    f.Proto,
			StreamID: f.StreamID,
			PktNo:    f.PktNo,
			FlowKey:  f.FlowKey,
			Buffer:   rule.Buffer(f.Buffer),
			Offset:   f.Offset,
			Snippet:  f.Snippet,
		},
	}
}

// alertModule 是告警模块的运行期实现。
//
// 生命周期：
//
//	OnStart → 建 FileSink + pollsource + Consumer，起 goroutine 后立即返回；
//	OnStop  → 先关 source（让 channel 排空）再关 consumer（冲刷 sink），幂等；
//	OnHealth→ 报"已投递/断层/错误/已写/已抑制"。
type alertModule struct {
	host plugin.Host

	mu      sync.Mutex
	started bool
	runErr  string

	src      *pollsource.Source
	consumer *Consumer
	sink     Sink
	sinkPath string

	cancel context.CancelFunc
	// convWg 等"解码转发"goroutine 退出（它负责 close 下游 channel）。
	convWg sync.WaitGroup
	// decodeErrs 是载荷 JSON 解析失败次数（Poll 层面的错误由 pollsource.Stats 报）。
	decodeErrs atomic.Uint64

	stopOnce sync.Once
}

// Module 返回告警模块定义（进程入口 cmd/plugins/alert 使用）。
//
// 对应 registry/backend-modules/alert.json：
//   - L2 具体功能；
//   - 无 HTTPBase（纯事件消费者）；
//   - 提供 alert.sink 服务名。
func Module() *plugin.Runtime {
	m := &alertModule{}
	return &plugin.Runtime{
		Spec: plugin.Manifest{
			ID:       "modules.alert",
			Name:     "告警服务",
			Version:  "0.1.0",
			Layer:    plugin.LayerFeature,
			Provides: []string{"alert.sink"},
		},
		OnStart:  m.start,
		OnStop:   m.stop,
		OnHealth: m.health,
	}
}

// start 解析配置、建落点与消费者、起后台 goroutine 后立即返回（不阻塞 Start）。
//
// ★ 失败（如落点打不开）只记 runErr 并写日志，由 Health 如实上报，
// 不让宿主因为一个可选消费者起不来而卡住启动。
func (m *alertModule) start(host plugin.Host, cfg plugin.ConfigSnapshot) error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return nil
	}
	m.host = host
	m.mu.Unlock()

	sinkPath := resolveSinkPath(cfg)
	if dir := filepath.Dir(sinkPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			m.setRunErr(fmt.Sprintf("alert: 创建告警目录 %s 失败: %v", dir, err))
			return nil
		}
	}
	sink, err := NewFileSink(sinkPath)
	if err != nil {
		m.setRunErr("alert: 打开告警落点失败: " + err.Error())
		return nil
	}

	src := pollsource.New(host, topicDetectFeature, pollsource.Options{})
	out := make(chan eventbus.Event, forwardBuffer)
	ctx, cancel := context.WithCancel(context.Background())
	cons := NewConsumer(out, sink, ConsumerOptions{})

	m.mu.Lock()
	m.src = src
	m.sink = sink
	m.sinkPath = sinkPath
	m.consumer = cons
	m.cancel = cancel
	m.started = true
	m.mu.Unlock()

	// 解码转发：pollsource 给的是 []byte 载荷，Consumer 需要 alert.Event。
	m.convWg.Add(1)
	go m.forward(src.C(), out)

	// ctx 取消 ⇒ 关 source（source 拥有 channel，关后转发 goroutine 自然收尾）。
	go func() {
		<-ctx.Done()
		m.closeSource()
	}()

	host.Log("info", "alert: 消费者已启动，订阅 "+topicDetectFeature+" → "+sinkPath)
	return nil
}

// forward 把事件载荷解码成 alert.Event 后投递给 Consumer。
//
// ★ 不丢事件：只有"解析失败"的坏载荷会被计数跳过；正常事件按背压阻塞投递。
func (m *alertModule) forward(in <-chan eventbus.Event, out chan<- eventbus.Event) {
	defer m.convWg.Done()
	defer close(out)

	for ev := range in {
		a, ok := decodeEvent(ev.Payload)
		if !ok {
			m.decodeErrs.Add(1)
			m.logf("warn", fmt.Sprintf("alert: 无法解析 %s 事件载荷（trace=%s）", topicDetectFeature, ev.TraceID))
			continue
		}
		out <- eventbus.Event{Topic: ev.Topic, Payload: a, TraceID: ev.TraceID, Time: ev.Time}
	}
}

// decodeEvent 把线上 JSON 解码成 alert.Event。
//
// 兼容三种形状：
//  1. 已经是 alert.Event（detect.Alert 默认字段名，如 "RuleID"）——直接使用；
//  2. 嵌套 alert 但用 snake_case（如 "alert":{"rule_id":...}）——映射；
//  3. capture 发布的扁平 detect.feature ——逐字段映射。
func decodeEvent(payload any) (Event, bool) {
	raw, ok := payloadBytes(payload)
	if !ok {
		return Event{}, false
	}

	var direct Event
	if err := json.Unmarshal(raw, &direct); err == nil && direct.Alert.RuleID != "" {
		return direct, true
	}

	var nested struct {
		CaptureID string       `json:"capture_id"`
		Alert     featureEvent `json:"alert"`
	}
	if err := json.Unmarshal(raw, &nested); err == nil && nested.Alert.RuleID != "" {
		ev := nested.Alert.toAlertEvent()
		ev.CaptureID = nested.CaptureID
		return ev, true
	}

	var f featureEvent
	if err := json.Unmarshal(raw, &f); err != nil {
		return Event{}, false
	}
	if f.RuleID == "" {
		return Event{}, false
	}
	return f.toAlertEvent(), true
}

// payloadBytes 从 eventbus.Event.Payload 取原始字节。
func payloadBytes(payload any) ([]byte, bool) {
	switch v := payload.(type) {
	case []byte:
		return v, true
	case json.RawMessage:
		return []byte(v), true
	case string:
		return []byte(v), true
	}
	return nil, false
}

// stop 取消 ctx、关 source、等转发 goroutine、关 consumer 与 sink（幂等）。
//
// ★ 顺序关键：先关 source（channel 关闭后 Consumer 会把缓冲读空再退出），
// 才能保证最后几条事件不被漏掉。
func (m *alertModule) stop() error {
	m.stopOnce.Do(func() {
		m.mu.Lock()
		cancel := m.cancel
		src := m.src
		cons := m.consumer
		sink := m.sink
		m.started = false
		m.mu.Unlock()

		if cancel != nil {
			cancel()
		}
		if src != nil {
			src.Close()
		}
		m.convWg.Wait()
		if cons != nil {
			_ = cons.Close()
			return
		}
		if sink != nil {
			_ = sink.Close()
		}
	})
	return nil
}

// health 返回真实运行态与消费进度。
func (m *alertModule) health() plugin.HealthStatus {
	m.mu.Lock()
	started, runErr := m.started, m.runErr
	src, cons := m.src, m.consumer
	m.mu.Unlock()

	if runErr != "" {
		return plugin.HealthStatus{Healthy: false, Message: runErr}
	}
	if !started {
		return plugin.HealthStatus{Healthy: false, Message: "alert: 未启动"}
	}

	var st pollsource.Stats
	if src != nil {
		st = src.Stats()
	}
	var written, suppressed uint64
	if cons != nil {
		written = cons.Written()
		suppressed = cons.Suppressed()
	}
	errs := st.Errors + m.decodeErrs.Load()
	return plugin.HealthStatus{
		Healthy: true,
		Message: fmt.Sprintf(
			"alert: 已投递 %d / 断层 %d / 错误 %d / 已写 %d / 已抑制 %d",
			st.Delivered, st.Gaps, errs, written, suppressed),
	}
}

// closeSource 关停 pollsource（幂等；ctx 取消与 OnStop 都会调用）。
func (m *alertModule) closeSource() {
	m.mu.Lock()
	src := m.src
	m.mu.Unlock()
	if src != nil {
		src.Close()
	}
}

// resolveSinkPath 从配置快照解析 alert.sink_path，缺省 data/alerts.jsonl。
func resolveSinkPath(cfg plugin.ConfigSnapshot) string {
	if cfg.Raw == "" {
		return defaultSinkPath
	}
	var rc rawConfig
	if err := json.Unmarshal([]byte(cfg.Raw), &rc); err != nil {
		return defaultSinkPath
	}
	if rc.Alert.SinkPath != "" {
		return rc.Alert.SinkPath
	}
	if rc.FlatPath != "" {
		return rc.FlatPath
	}
	return defaultSinkPath
}

// setRunErr 记录失败原因并写宿主日志（Health 会如实上报）。
func (m *alertModule) setRunErr(msg string) {
	m.mu.Lock()
	m.runErr = msg
	m.mu.Unlock()
	m.logf("error", msg)
}

// logf 写宿主日志（host 为空时静默）。
func (m *alertModule) logf(level, msg string) {
	m.mu.Lock()
	host := m.host
	m.mu.Unlock()
	if host != nil {
		host.Log(level, msg)
	}
}
