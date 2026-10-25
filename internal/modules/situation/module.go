package situation

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"flow-monitoring/internal/kernel/eventbus"
	"flow-monitoring/internal/modules/common/pollsource"
	"flow-monitoring/pkg/plugin"
)

const (
	// topicDetectFeature 是检测特征事件主题（capture 进程发布）。
	topicDetectFeature = "detect.feature"
	// topicSituationLevel 是本模块发布的威胁等级变化主题。
	topicSituationLevel = "situation.level"
	// httpBase 是模块对外 HTTP 路由前缀（与 registry/backend-modules/situation.json 一致）。
	httpBase = "/api/situation"
)

// featureEvent 是 detect.feature 载荷中本模块需要的字段。
//
// ★ 只需 src_ip / rule_id / weight 即可算分，不依赖生产者实现：
// 消费者只认"线上 JSON 的形状"，多余字段一律忽略。
type featureEvent struct {
	RuleID string `json:"rule_id"`
	Weight int    `json:"weight"`
	SrcIP  string `json:"src_ip"`
}

// situationSettings 是 situation 私有配置段。
type situationSettings struct {
	WindowSec       int   `json:"window_sec"`
	LowThreshold    int64 `json:"low_threshold"`
	MediumThreshold int64 `json:"medium_threshold"`
	HighThreshold   int64 `json:"high_threshold"`
}

// situationModule 是态势评估模块的运行期实现。
//
// 生命周期：
//
//	MakeHandler → 固定宿主桥并暴露 GET /api/situation 与 /api/situation/stats；
//	OnStart     → 解析配置、启动 pollsource 消费 detect.feature（起 goroutine 后立即返回）；
//	OnStop      → 关 source、等消费 goroutine 退出（幂等）；
//	OnHealth    → 报 tracked_ips / received / decode_errors / level_changes / top_score。
type situationModule struct {
	host plugin.Host
	eng  *engine

	mu      sync.Mutex
	started bool
	runErr  string

	src *pollsource.Source
	wg  sync.WaitGroup

	stopOnce sync.Once
}

// Module 返回态势评估模块定义（进程入口 cmd/plugins/situation 使用）。
//
// 对应 registry/backend-modules/situation.json：
//   - L2 具体功能；
//   - HTTPBase = /api/situation（供前端查当前态势）；
//   - 提供 situation.level 服务名，注入 detect.feature。
func Module() *plugin.Runtime {
	m := newModule()
	return &plugin.Runtime{
		Spec: plugin.Manifest{
			ID:       "modules.situation",
			Name:     "态势评估引擎",
			Version:  "0.1.0",
			Layer:    plugin.LayerFeature,
			HTTPBase: httpBase,
			Provides: []string{topicSituationLevel},
			Injects:  []string{topicDetectFeature},
		},
		// ★ MakeHandler 在 OnStart 之前执行：此刻把宿主桥固定下来，
		//   之后 HTTP handler 的查询不再与 OnStart 竞争。
		MakeHandler: func(host plugin.Host) (http.Handler, error) {
			m.attachHost(host)
			return m.handler(), nil
		},
		OnStart:  m.start,
		OnStop:   m.stop,
		OnHealth: m.health,
	}
}

// newModule 创建模块实例（测试直接构造时使用）。
func newModule() *situationModule {
	return &situationModule{eng: newEngine(defaultEngineConfig())}
}

// attachHost 固定宿主桥（幂等；MakeHandler 与测试路径共用）。
func (m *situationModule) attachHost(host plugin.Host) {
	m.mu.Lock()
	if m.host == nil {
		m.host = host
	}
	m.mu.Unlock()
}

// start 解析配置、启动事件消费 goroutine 后立即返回（不阻塞 Start）。
func (m *situationModule) start(host plugin.Host, cfg plugin.ConfigSnapshot) error {
	m.attachHost(host)

	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	settings := resolveSettings(cfg)
	m.eng.configure(engineConfig{
		window: time.Duration(settings.WindowSec) * time.Second,
		low:    settings.LowThreshold,
		medium: settings.MediumThreshold,
		high:   settings.HighThreshold,
	})

	src := pollsource.New(host, topicDetectFeature, pollsource.Options{})

	m.mu.Lock()
	m.src = src
	m.started = true
	m.mu.Unlock()

	m.wg.Add(1)
	go m.consume(src.C())

	m.logf("info", fmt.Sprintf(
		"situation: 已启动，订阅 %s（窗口 %ds，阈值 %d/%d/%d）",
		topicDetectFeature, settings.WindowSec,
		settings.LowThreshold, settings.MediumThreshold, settings.HighThreshold))
	return nil
}

// consume 解码 detect.feature 并喂给评分引擎。
//
// ★ 不丢正常事件（背压由 pollsource 保证）；只有解析失败/缺 src_ip 的坏载荷
//
//	会被计数跳过。等级变化事件在引擎锁外发布。
func (m *situationModule) consume(in <-chan eventbus.Event) {
	defer m.wg.Done()
	for ev := range in {
		f, ok := decodeFeature(ev.Payload)
		if !ok {
			m.eng.incDecodeError()
			m.logf("warn", fmt.Sprintf("situation: 无法解析 %s 事件载荷（trace=%s）", topicDetectFeature, ev.TraceID))
			continue
		}
		m.publishChanges(m.eng.record(f.SrcIP, f.RuleID, int64(f.Weight)))
	}
}

// stop 关 source 并等待消费 goroutine 退出（幂等）。
func (m *situationModule) stop() error {
	m.stopOnce.Do(func() {
		m.mu.Lock()
		src := m.src
		m.started = false
		m.mu.Unlock()

		if src != nil {
			src.Close()
		}
		m.wg.Wait()
	})
	return nil
}

// health 返回运行状态与指标。
func (m *situationModule) health() plugin.HealthStatus {
	m.mu.Lock()
	started, runErr := m.started, m.runErr
	m.mu.Unlock()

	st := m.eng.stats()
	metrics := map[string]string{
		"tracked_ips":   strconv.Itoa(st.TrackedIPs),
		"received":      strconv.FormatUint(st.Received, 10),
		"decode_errors": strconv.FormatUint(st.DecodeErrors, 10),
		"level_changes": strconv.FormatUint(st.LevelChanges, 10),
		"top_score":     strconv.FormatInt(st.TopScore, 10),
	}

	if runErr != "" {
		return plugin.HealthStatus{Healthy: false, Message: runErr, Metrics: metrics}
	}
	if !started {
		return plugin.HealthStatus{Healthy: false, Message: "situation: 未启动", Metrics: metrics}
	}
	return plugin.HealthStatus{
		Healthy: true,
		Message: fmt.Sprintf(
			"situation: 跟踪 %d 个 IP / 已收 %d / 解码错误 %d / 等级变化 %d / 最高分 %d",
			st.TrackedIPs, st.Received, st.DecodeErrors, st.LevelChanges, st.TopScore),
		Metrics: metrics,
	}
}

// publishChanges 在引擎锁外发布等级变化事件。
func (m *situationModule) publishChanges(changes []levelChange) {
	if len(changes) == 0 {
		return
	}
	m.mu.Lock()
	host := m.host
	m.mu.Unlock()
	if host == nil {
		return
	}
	for _, ch := range changes {
		data, err := json.Marshal(ch)
		if err != nil {
			continue
		}
		if err := host.Publish(topicSituationLevel, data); err != nil {
			m.logf("warn", "situation: 发布 "+topicSituationLevel+" 失败: "+err.Error())
		}
	}
}

// isStarted 报告模块是否已启动（供 /stats 的 enabled 字段）。
func (m *situationModule) isStarted() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.started
}

// logf 写宿主日志（host 为空时静默）。
func (m *situationModule) logf(level, msg string) {
	m.mu.Lock()
	host := m.host
	m.mu.Unlock()
	if host != nil {
		host.Log(level, msg)
	}
}

// decodeFeature 把线上 JSON 载荷解码成 featureEvent。
//
// 兼容 []byte / json.RawMessage / string 三种 Payload 形态。
// 解析失败、rule 为空、src_ip 为空都视为坏载荷（无法聚合）。
func decodeFeature(payload any) (featureEvent, bool) {
	raw, ok := payloadBytes(payload)
	if !ok {
		return featureEvent{}, false
	}
	var f featureEvent
	if err := json.Unmarshal(raw, &f); err != nil {
		return featureEvent{}, false
	}
	if f.SrcIP == "" || f.RuleID == "" {
		return featureEvent{}, false
	}
	return f, true
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

// resolveSettings 解析 situation 私有配置，缺省用 defaults。
//
// 为了兼容宿主配置快照的几种形态，依次尝试（后者覆盖前者）：
//  1. 顶层 "situation" 对象；
//  2. "extra" 下的 "situation" 对象；
//  3. "extra" 下的扁平点号键（如 situation.low_threshold）；
//  4. 顶层扁平点号键。
func resolveSettings(cfg plugin.ConfigSnapshot) situationSettings {
	s := situationSettings{
		WindowSec:       defaultWindowSec,
		LowThreshold:    defaultLowThreshold,
		MediumThreshold: defaultMediumThreshold,
		HighThreshold:   defaultHighThreshold,
	}
	if cfg.Raw == "" {
		return s
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(cfg.Raw), &top); err != nil {
		return s
	}

	// 1. 顶层 situation 对象。
	if raw, ok := top["situation"]; ok {
		_ = json.Unmarshal(raw, &s)
	}

	// 2. extra 下的对象 / 扁平键。
	if raw, ok := top["extra"]; ok {
		var extra map[string]json.RawMessage
		if json.Unmarshal(raw, &extra) == nil {
			if v, ok := extra["situation"]; ok {
				_ = json.Unmarshal(v, &s)
			}
			applyFlatSettings(extra, &s)
		}
	}

	// 3. 顶层扁平键（优先级最高）。
	applyFlatSettings(top, &s)

	return normalizeSettings(s)
}

// applyFlatSettings 把 map 里的 "situation.*" 扁平键写入 settings。
// 不存在的键保持原值。
func applyFlatSettings(m map[string]json.RawMessage, s *situationSettings) {
	applyInt(m, "situation.window_sec", &s.WindowSec)
	applyInt64(m, "situation.low_threshold", &s.LowThreshold)
	applyInt64(m, "situation.medium_threshold", &s.MediumThreshold)
	applyInt64(m, "situation.high_threshold", &s.HighThreshold)
}

// applyInt 若键存在则解成 int 写入 dst。
func applyInt(m map[string]json.RawMessage, key string, dst *int) {
	if raw, ok := m[key]; ok {
		var v int
		if json.Unmarshal(raw, &v) == nil {
			*dst = v
		}
	}
}

// applyInt64 若键存在则解成 int64 写入 dst。
func applyInt64(m map[string]json.RawMessage, key string, dst *int64) {
	if raw, ok := m[key]; ok {
		var v int64
		if json.Unmarshal(raw, &v) == nil {
			*dst = v
		}
	}
}

// normalizeSettings 兜住非法阈值（必须为正且严格递增）。
func normalizeSettings(s situationSettings) situationSettings {
	if s.WindowSec <= 0 {
		s.WindowSec = defaultWindowSec
	}
	if s.LowThreshold <= 0 {
		s.LowThreshold = defaultLowThreshold
	}
	if s.MediumThreshold <= s.LowThreshold {
		s.MediumThreshold = s.LowThreshold + 1
	}
	if s.HighThreshold <= s.MediumThreshold {
		s.HighThreshold = s.MediumThreshold + 1
	}
	return s
}
