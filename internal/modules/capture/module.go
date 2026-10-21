package capture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"flow-monitoring/internal/hotpath"
	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/modules/detect"
	"flow-monitoring/internal/modules/parse/decoder"
	"flow-monitoring/pkg/plugin"
)

// topicDetectFeature 检测特征事件主题。
//
// ★ 刻意用字符串常量，不 import internal/modules/alert：
// capture 只负责产出检测特征，不依赖具体消费者，避免把告警模块拖进本进程。
const topicDetectFeature = "detect.feature"

// modeLive 是本阶段唯一实际产出的工作台归属（静态分析到阶段 3 接入）。
const modeLive = "live"

// detectSettings 是本模块从 ConfigSnapshot.Raw 里解析的私有配置段。
// 字段 json tag 与 internal/kernel/config.DetectConfig 保持一致。
type detectSettings struct {
	RulesDir   string `json:"rules_dir"`
	ReplayFile string `json:"replay_file"`
}

// featureEvent 是 detect.feature 主题的事件载荷。
//
// 扁平化输出告警关键字段，便于下游（态势/攻击链）直接消费；
// rule_id 是稳定契约字段。
type featureEvent struct {
	CaptureID string `json:"capture_id,omitempty"`
	// 分析任务归属：run_id 标识一次分析任务，mode 标识工作台（阶段 2 恒为 live）。
	// 两者用 omitempty，旧消费者不受影响。
	RunID    string    `json:"run_id,omitempty"`
	Mode     string    `json:"mode,omitempty"`
	RuleID   string    `json:"rule_id"`
	Name     string    `json:"name,omitempty"`
	Severity string    `json:"severity,omitempty"`
	Weight   int       `json:"weight,omitempty"`
	Time     time.Time `json:"time"`
	SrcIP    string    `json:"src_ip,omitempty"`
	SrcPort  uint16    `json:"src_port,omitempty"`
	DstIP    string    `json:"dst_ip,omitempty"`
	DstPort  uint16    `json:"dst_port,omitempty"`
	Proto    string    `json:"proto,omitempty"`
	StreamID int       `json:"stream_id"`
	PktNo    int       `json:"pkt_no"`
	FlowKey  string    `json:"flow_key,omitempty"`
	Buffer   string    `json:"buffer,omitempty"`
	Offset   int       `json:"offset"`
	Snippet  string    `json:"snippet,omitempty"`
}

// captureModule 是采集模块的运行期实现。
//
// 与 Runtime 的关系：Module() 把 start/stop/health 三个钩子挂到
// plugin.Runtime，Runtime 只负责进程级公共样板（回连宿主、生命周期），
// 采集/热路径/事件发布全在本结构内。
type captureModule struct {
	host plugin.Host

	source Source
	hp     *hotpath.Hotpath

	cancel   context.CancelFunc
	wg       sync.WaitGroup
	stopOnce sync.Once

	mu         sync.Mutex
	started    bool
	runErr     string // 非空 ⇒ 数据源/规则加载失败（Health 如实上报）
	panicCount int    // 被 recover 的坏包数（观测用）

	// 测试注入口；nil 时使用生产实现。
	newSource func(path string) (Source, error)
	process   func(hp *hotpath.Hotpath, p *datamodel.Packet) []detect.Alert
}

// Module 返回采集模块定义（进程入口 cmd/plugins/capture 使用）。
//
// 对应 registry/backend-modules/capture.json：
//   - L1 基础功能；
//   - 不对外提供 HTTP（HTTPBase 留空）；
//   - 发布 detect.feature 事件主题。
func Module() *plugin.Runtime {
	m := &captureModule{}
	return &plugin.Runtime{
		Spec: plugin.Manifest{
			ID:       "modules.capture",
			Name:     "采集与检测",
			Version:  "0.1.0",
			Layer:    plugin.LayerFoundation,
			Provides: []string{"capture.core", "detect.feature"},
		},
		OnStart:  m.start,
		OnStop:   m.stop,
		OnHealth: m.health,
	}
}

// start 解析配置、加载规则、准备数据源，并起后台回放协程后立即返回。
//
// ★ 加载失败不阻塞 Start：错误记入 runErr，由 Health 如实上报
//
//	（这样宿主有机会看到"模块活着但不健康"的明确原因）。
func (m *captureModule) start(host plugin.Host, cfg plugin.ConfigSnapshot) error {
	m.host = host

	m.mu.Lock()
	m.started = true
	m.mu.Unlock()

	var root struct {
		Detect detectSettings `json:"detect"`
	}
	if err := json.Unmarshal([]byte(cfg.Raw), &root); err != nil {
		m.setRunErr(fmt.Sprintf("capture: 解析配置失败: %v", err))
		return nil
	}
	settings := root.Detect
	if settings.RulesDir == "" {
		m.setRunErr("capture: detect.rules_dir 为空，无法加载规则")
		return nil
	}
	if settings.ReplayFile == "" {
		m.setRunErr("capture: detect.replay_file 为空，没有数据源")
		return nil
	}

	rs, report := detect.LoadDir(settings.RulesDir)
	if rs == nil || report == nil {
		m.setRunErr(fmt.Sprintf("capture: 加载规则目录 %q 失败", settings.RulesDir))
		return nil
	}
	// LoadDir 不返回 error（错误体现在报告里）：目录不可读/缺失时
	// Total==0 且 Issues 非空。此时视为规则加载失败。
	if report.Total == 0 && len(report.Issues) > 0 {
		m.setRunErr("capture: 加载规则目录 " + settings.RulesDir + " 失败: " + report.Issues[0])
		return nil
	}
	hp := hotpath.New(rs)

	mk := m.newSource
	if mk == nil {
		mk = func(path string) (Source, error) { return NewReplaySource(path) }
	}
	src, err := mk(settings.ReplayFile)
	if err != nil {
		hp.Close()
		m.setRunErr("capture: 打开数据源失败: " + err.Error())
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	m.mu.Lock()
	m.hp = hp
	m.source = src
	m.cancel = cancel
	m.mu.Unlock()

	m.wg.Add(1)
	go m.run(ctx, src, hp)
	return nil
}

// stop 取消后台回放、关闭数据源与热路径（幂等）。
func (m *captureModule) stop() error {
	var firstErr error
	m.stopOnce.Do(func() {
		m.mu.Lock()
		cancel := m.cancel
		src := m.source
		hp := m.hp
		m.cancel = nil
		m.source = nil
		m.hp = nil
		m.started = false
		m.mu.Unlock()

		if cancel != nil {
			cancel()
		}
		m.wg.Wait()
		if src != nil {
			if err := src.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if hp != nil {
			hp.Close()
		}
	})
	return firstErr
}

// health 返回真实运行态：加载失败 ⇒ 不健康；运行中/正常结束 ⇒ 健康。
func (m *captureModule) health() plugin.HealthStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.runErr != "" {
		return plugin.HealthStatus{Healthy: false, Message: m.runErr}
	}
	if !m.started {
		return plugin.HealthStatus{Healthy: false, Message: "capture: 未启动"}
	}
	return plugin.HealthStatus{Healthy: true}
}

// run 是后台主循环：逐帧读取 → 解码 → 检测 → 发布 detect.feature。
func (m *captureModule) run(ctx context.Context, src Source, hp *hotpath.Hotpath) {
	defer m.wg.Done()

	packets := 0
	alerts := 0
	publishErrs := 0
	captureID := src.Describe()
	// run_id 在本次分析任务启动时生成一次，格式 run-<unixnano>；cross-process 唯一即可。
	runID := fmt.Sprintf("run-%d", time.Now().UnixNano())

	for {
		frame, err := src.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			m.setRunErr(fmt.Sprintf("capture: 读取数据源失败: %v", err))
			return
		}

		packets++
		hits := m.processFrame(hp, frame, packets)
		for _, h := range hits {
			alerts++
			payload, err := json.Marshal(newFeatureEvent(captureID, runID, modeLive, h))
			if err != nil {
				publishErrs++
				m.host.Log("error", fmt.Sprintf("capture: 序列化告警 %s 失败: %v", h.RuleID, err))
				continue
			}
			if err := m.host.Publish(topicDetectFeature, payload); err != nil {
				publishErrs++
				m.host.Log("error", fmt.Sprintf("capture: 发布告警 %s 失败: %v", h.RuleID, err))
			}
		}
	}

	m.host.Log("info", fmt.Sprintf(
		"capture: replay finished, packets=%d alerts=%d publish_errs=%d",
		packets, alerts, publishErrs))
}

// processFrame 解码并处理单帧；recover 保证一个坏包不会打死整个进程（技术债 #10）。
func (m *captureModule) processFrame(hp *hotpath.Hotpath, frame Frame, no int) (hits []detect.Alert) {
	defer func() {
		if r := recover(); r != nil {
			m.mu.Lock()
			m.panicCount++
			m.mu.Unlock()
			m.host.Log("error", fmt.Sprintf("capture: packet %d panic recovered: %v", no, r))
			hits = nil
		}
	}()

	p := datamodel.NewPacket()
	p.No = no
	p.Data = frame.Data
	p.CapLen = len(frame.Data)
	p.OrigLen = len(frame.Data)
	p.Time = frame.TS

	decoder.Decode(p, frame.LinkType)

	if m.process != nil {
		return m.process(hp, p)
	}
	return hp.Process(p)
}

// setRunErr 记录失败原因并写宿主日志（Health 会如实上报）。
func (m *captureModule) setRunErr(msg string) {
	m.mu.Lock()
	m.runErr = msg
	m.mu.Unlock()
	if m.host != nil {
		m.host.Log("error", msg)
	}
}

// newFeatureEvent 把检测告警转成 detect.feature 的稳定 JSON 结构。
func newFeatureEvent(captureID, runID, mode string, a detect.Alert) featureEvent {
	return featureEvent{
		CaptureID: captureID,
		RunID:     runID,
		Mode:      mode,
		RuleID:    a.RuleID,
		Name:      a.Name,
		Severity:  a.Severity,
		Weight:    a.Weight,
		Time:      a.Time,
		SrcIP:     a.SrcIP,
		SrcPort:   a.SrcPort,
		DstIP:     a.DstIP,
		DstPort:   a.DstPort,
		Proto:     a.Proto,
		StreamID:  a.StreamID,
		PktNo:     a.PktNo,
		FlowKey:   a.FlowKey,
		Buffer:    string(a.Buffer),
		Offset:    a.Offset,
		Snippet:   a.Snippet,
	}
}
