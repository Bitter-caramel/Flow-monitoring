package capture

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
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

// Run 的两种工作台归属：live 是启动时自动回放，static 是按 HTTP 请求
// 分析已导入的抓包文件。
const (
	modeLive   = "live"
	modeStatic = "static"
)

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

	wg       sync.WaitGroup
	stopOnce sync.Once

	mu         sync.Mutex
	started    bool
	stopped    bool
	runErr     string // 非空 ⇒ 数据源/规则加载失败（Health 如实上报）
	panicCount int    // 被 recover 的坏包数（观测用）

	// 规则集只读，可被多个 Run 共享；每个 Run 各自新建 hotpath。
	ruleset *detect.RuleSet
	dataDir string
	maxRuns int
	runs    map[string]*captureRun

	// 测试注入口；nil 时使用生产实现。
	newSource func(path string) (Source, error)
	process   func(hp *hotpath.Hotpath, p *datamodel.Packet) []detect.Alert
}

// Module 返回采集模块定义（进程入口 cmd/plugins/capture 使用）。
//
// 对应 registry/backend-modules/capture.json：
//   - L1 基础功能；
//   - 对外提供 /api/capture HTTP 路由（Run 管理），由宿主网关反代；
//   - 发布 detect.feature 事件主题。
func Module() *plugin.Runtime {
	m := &captureModule{}
	return &plugin.Runtime{
		Spec: plugin.Manifest{
			ID:       "modules.capture",
			Name:     "采集与检测",
			Version:  "0.1.0",
			Layer:    plugin.LayerFoundation,
			HTTPBase: httpBase,
			Provides: []string{"capture.core", "detect.feature"},
		},
		// ★ MakeHandler 在 OnStart 之前执行：此刻把宿主桥与 DataDir 固定下来，
		// 之后 handler 里的只读访问不再与 OnStart 竞争。
		MakeHandler: func(host plugin.Host) (http.Handler, error) {
			m.attachHost(host)
			return m.handler(), nil
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
	m.attachHost(host)

	m.mu.Lock()
	m.started = true
	m.stopped = false
	m.ensureRunsLocked()
	if m.dataDir == "" {
		m.dataDir = cfg.DataDir
	}
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
	// 规则集只读，多个 Run 共享；hotpath 由每个 Run 各自新建。
	m.mu.Lock()
	m.ruleset = rs
	m.mu.Unlock()

	// 18a：从宿主存储回填 Run 历史（重启不丢"分析过哪些证据包、结果如何"）。
	// 必须在创建 live Run 之前完成，避免历史与本次新 Run 的 ID/状态混淆。
	m.restoreRuns()

	// detect.replay_file 为空 ⇒ 不自动开播，等待 HTTP 下发的静态分析任务。
	if settings.ReplayFile == "" {
		m.host.Log("info", "capture: detect.replay_file 为空，等待静态分析任务")
		return nil
	}

	src, err := m.openSource(settings.ReplayFile)
	if err != nil {
		m.setRunErr("capture: 打开数据源失败: " + err.Error())
		return nil
	}
	// ★ capture_id 传空：live Run 没有"已导入的抓包文件"这一归属。
	//   数据源信息已经在 source 里（如 "replay:sqli.pcapng"），不要塞进 capture_id 伪造归属。
	if _, err := m.addRun(modeLive, src.Describe(), "", src); err != nil {
		_ = src.Close()
		m.setRunErr("capture: 创建 live Run 失败: " + err.Error())
		return nil
	}
	return nil
}

// attachHost 固定宿主桥与 DataDir（幂等；MakeHandler 与测试路径共用）。
//
// ★ 只写一次（nil 时），之后 handler 的只读访问不会与 OnStart 竞争。
func (m *captureModule) attachHost(host plugin.Host) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.host == nil {
		m.host = host
	}
	if m.dataDir == "" && host != nil {
		m.dataDir = host.Config().DataDir
	}
}

// openSource 按需打开数据源；测试可注入 newSource。
func (m *captureModule) openSource(path string) (Source, error) {
	if m.newSource != nil {
		return m.newSource(path)
	}
	return NewReplaySource(path)
}

// stop 取消所有 Run、等待它们退出并关闭各自的 hotpath（幂等）。
func (m *captureModule) stop() error {
	var firstErr error
	m.stopOnce.Do(func() {
		m.mu.Lock()
		m.started = false
		m.stopped = true
		runs := make([]*captureRun, 0, len(m.runs))
		for _, r := range m.runs {
			runs = append(runs, r)
		}
		m.mu.Unlock()

		for _, r := range runs {
			if r.cancel != nil {
				r.cancel()
			}
		}
		m.wg.Wait()

		for _, r := range runs {
			if r.hp != nil {
				r.hp.Close()
			}
			if r.src != nil {
				if err := r.src.Close(); err != nil && firstErr == nil {
					firstErr = err
				}
			}
		}
	})
	return firstErr
}

// health 返回真实运行态：加载失败 ⇒ 不健康；运行中/正常结束 ⇒ 健康。
//
// 无论健康与否都带上运行指标（Metrics），供宿主 /api/modules 展示。
func (m *captureModule) health() plugin.HealthStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	metrics := m.metricsLocked()
	if m.runErr != "" {
		return plugin.HealthStatus{Healthy: false, Message: m.runErr, Metrics: metrics}
	}
	if !m.started {
		return plugin.HealthStatus{Healthy: false, Message: "capture: 未启动", Metrics: metrics}
	}
	return plugin.HealthStatus{Healthy: true, Metrics: metrics}
}

// metricsLocked 汇总采集模块的运行指标；调用方必须持有 m.mu。
//
//	packets_total 所有 Run 累计处理包数
//	alerts_total  所有 Run 累计命中的告警数
//	rules_total   已加载并成功编译的规则数
//	runs_running  正在运行的 Run 数
//	runs_total    当前保留的 Run 总数（含已结束）
//
// ★ 数值一律 strconv.FormatInt 转字符串（gob 安全）。
func (m *captureModule) metricsLocked() map[string]string {
	var packets, alerts int
	for _, r := range m.runs {
		packets += r.Packets
		alerts += r.Alerts
	}
	rules := 0
	if m.ruleset != nil {
		rules = len(m.ruleset.Programs)
	}
	return map[string]string{
		"packets_total": strconv.FormatInt(int64(packets), 10),
		"alerts_total":  strconv.FormatInt(int64(alerts), 10),
		"rules_total":   strconv.FormatInt(int64(rules), 10),
		"runs_running":  strconv.FormatInt(int64(m.countRunningLocked()), 10),
		"runs_total":    strconv.FormatInt(int64(len(m.runs)), 10),
	}
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
