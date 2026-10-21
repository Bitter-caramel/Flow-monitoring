package capture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync/atomic"
	"time"

	"flow-monitoring/internal/hotpath"
)

// Run 状态与容量默认值。
const (
	runStateRunning = "running"
	runStateDone    = "done"
	runStateError   = "error"

	// defaultMaxRuns 是**同时运行**的 Run 上限（只统计 state==running）。
	// 达到上限时新建请求返回 409，不静默排队。
	// ★ 已结束（done/error）的 Run 不占并发名额 —— 否则分析几次之后就再也建不了新 Run。
	defaultMaxRuns = 4

	// keepFinishedRuns 是保留在 runs 表里的已结束 Run 上限（供查询历史）；
	// 超出时淘汰最早结束的，避免无限累积。
	keepFinishedRuns = 50

	// stopRunWait 是 DELETE 等待 Run 协程退出的上限，避免慢数据源把 HTTP 拖死。
	stopRunWait = 5 * time.Second
)

// Run 创建/停止相关的哨兵错误。
var (
	errTooManyRuns = errors.New("capture: Run 数已达上限")
	errNotRunning  = errors.New("capture: 模块未运行")
	errNoRules     = errors.New("capture: 规则集尚未就绪")
)

// runSeq 保证同一进程内、跨模块实例的 run_id 也唯一。
var runSeq uint64

// newRunID 生成并发唯一的 Run ID（unixnano + 原子序号）。
func newRunID() string {
	return fmt.Sprintf("run-%d-%d", time.Now().UnixNano(), atomic.AddUint64(&runSeq, 1))
}

// captureRun 是一次分析任务（Run）的运行期状态。
//
// 前 9 个字段是对外可见的 Run JSON；其余是运行期私有状态。
// ★ src / hp 每个 Run 独立持有，绝不能跨 Run 共享（归流表与重组缓冲有状态）。
type captureRun struct {
	ID       string    `json:"id"`
	Mode     string    `json:"mode"`
	Source   string    `json:"source"`
	State    string    `json:"state"`
	Packets  int       `json:"packets"`
	Alerts   int       `json:"alerts"`
	Err      string    `json:"err,omitempty"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`

	captureID string
	src       Source
	hp        *hotpath.Hotpath
	cancel    context.CancelFunc
	done      chan struct{}
}

// runView 是 captureRun 的只读快照（JSON 输出用）。
type runView struct {
	ID        string    `json:"id"`
	Mode      string    `json:"mode"`
	Source    string    `json:"source"`
	CaptureID string    `json:"capture_id,omitempty"`
	State     string    `json:"state"`
	Packets   int       `json:"packets"`
	Alerts    int       `json:"alerts"`
	Err       string    `json:"err,omitempty"`
	Started   time.Time `json:"started"`
	Finished  time.Time `json:"finished"`
}

// runViewOf 读取 Run 的只读快照；调用方必须持有 m.mu。
func runViewOf(r *captureRun) runView {
	return runView{
		ID:        r.ID,
		Mode:      r.Mode,
		Source:    r.Source,
		CaptureID: r.captureID,
		State:     r.State,
		Packets:   r.Packets,
		Alerts:    r.Alerts,
		Err:       r.Err,
		Started:   r.Started,
		Finished:  r.Finished,
	}
}

// ensureRunsLocked 初始化 runs 表与 maxRuns 默认值；调用方必须持有 m.mu。
func (m *captureModule) ensureRunsLocked() {
	if m.runs == nil {
		m.runs = make(map[string]*captureRun)
	}
	if m.maxRuns <= 0 {
		m.maxRuns = defaultMaxRuns
	}
}

// addRun 在容量允许时登记并启动一个新的 Run。
//
// 返回 errTooManyRuns / errNotRunning / errNoRules 供 HTTP 层映射状态码。
// ★ hotpath 在这里按 Run 新建（共享只读 RuleSet），保证状态隔离。
func (m *captureModule) addRun(mode, sourceName, captureID string, src Source) (*captureRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ensureRunsLocked()
	if !m.started || m.stopped {
		return nil, errNotRunning
	}
	if m.ruleset == nil {
		return nil, errNoRules
	}
	if m.countRunningLocked() >= m.maxRuns {
		return nil, errTooManyRuns
	}

	ctx, cancel := context.WithCancel(context.Background())
	run := &captureRun{
		ID:        newRunID(),
		Mode:      mode,
		Source:    sourceName,
		State:     runStateRunning,
		Started:   time.Now(),
		captureID: captureID,
		src:       src,
		hp:        hotpath.New(m.ruleset),
		cancel:    cancel,
		done:      make(chan struct{}),
	}
	m.runs[run.ID] = run
	m.evictFinishedLocked()
	m.wg.Add(1)
	go m.executeRun(ctx, run)
	return run, nil
}

// countRunningLocked 统计正在运行的 Run 数；调用方必须持有 m.mu。
func (m *captureModule) countRunningLocked() int {
	n := 0
	for _, r := range m.runs {
		if r.State == runStateRunning {
			n++
		}
	}
	return n
}

// evictFinishedLocked 在已结束 Run 超过保留上限时淘汰最早结束的；调用方必须持有 m.mu。
//
// ★ 只淘汰 done/error，绝不淘汰 running —— 运行中的 Run 正被自己的 goroutine 持有。
func (m *captureModule) evictFinishedLocked() {
	finished := make([]*captureRun, 0, len(m.runs))
	for _, r := range m.runs {
		if r.State != runStateRunning {
			finished = append(finished, r)
		}
	}
	if len(finished) <= keepFinishedRuns {
		return
	}
	sort.Slice(finished, func(i, j int) bool {
		if finished[i].Finished.Equal(finished[j].Finished) {
			return finished[i].ID < finished[j].ID
		}
		return finished[i].Finished.Before(finished[j].Finished)
	})
	for _, r := range finished[:len(finished)-keepFinishedRuns] {
		delete(m.runs, r.ID)
	}
}

// executeRun 是单个 Run 的主循环：逐帧读取 → 检测 → 发布 detect.feature。
//
// 每个 Run 用自己的 hotpath，与其它 Run 完全隔离；规则集只读共享。
func (m *captureModule) executeRun(ctx context.Context, run *captureRun) {
	defer m.wg.Done()
	defer close(run.done)
	defer run.hp.Close()
	defer func() {
		if run.src == nil {
			return
		}
		if err := run.src.Close(); err != nil {
			m.logf("warn", "capture: 关闭数据源失败: %v", err)
		}
	}()

	packets := 0
	alerts := 0
	publishErrs := 0

	for {
		frame, err := run.src.Next(ctx)
		if errors.Is(err, io.EOF) {
			m.finishRun(run, runStateDone, "", packets, alerts, publishErrs)
			return
		}
		if err != nil {
			if ctx.Err() != nil {
				// DELETE / OnStop：按“正常停止”收尾，状态为 done。
				m.finishRun(run, runStateDone, "", packets, alerts, publishErrs)
				return
			}
			msg := fmt.Sprintf("capture: 读取数据源失败: %v", err)
			m.recordRunErr(run, msg)
			m.finishRun(run, runStateError, msg, packets, alerts, publishErrs)
			return
		}

		packets++
		hits := m.processFrame(run.hp, frame, packets)
		for _, h := range hits {
			alerts++
			// 归属：run_id 用本 Run 的 ID，mode 用本 Run 的 mode。
			payload, err := json.Marshal(newFeatureEvent(run.captureID, run.ID, run.Mode, h))
			if err != nil {
				publishErrs++
				m.logf("error", "capture: 序列化告警 %s 失败: %v", h.RuleID, err)
				continue
			}
			if err := m.host.Publish(topicDetectFeature, payload); err != nil {
				publishErrs++
				m.logf("error", "capture: 发布告警 %s 失败: %v", h.RuleID, err)
			}
		}
		m.updateRunProgress(run, packets, alerts)
	}
}

// updateRunProgress 把进行中的计数写回 Run（供 GET /runs 观察进度）。
func (m *captureModule) updateRunProgress(run *captureRun, packets, alerts int) {
	m.mu.Lock()
	run.Packets = packets
	run.Alerts = alerts
	m.mu.Unlock()
}

// finishRun 落定 Run 的最终状态并写结束日志。
func (m *captureModule) finishRun(run *captureRun, state, errMsg string, packets, alerts, publishErrs int) {
	m.mu.Lock()
	run.State = state
	run.Packets = packets
	run.Alerts = alerts
	run.Finished = time.Now()
	if errMsg != "" {
		run.Err = errMsg
	}
	m.mu.Unlock()

	m.logf("info", "capture: replay finished, packets=%d alerts=%d publish_errs=%d",
		packets, alerts, publishErrs)
}

// recordRunErr 处理读源失败：live Run 保持历史行为（同时把模块置为不健康），
// static Run 只记录到该 Run，不影响整个模块的健康。
func (m *captureModule) recordRunErr(run *captureRun, msg string) {
	if run.Mode == modeLive {
		m.setRunErr(msg)
		return
	}
	m.logf("error", "%s", msg)
}

// logf 写宿主日志（host 可能尚未注入的测试路径下安全跳过）。
func (m *captureModule) logf(level, format string, args ...any) {
	if m.host != nil {
		m.host.Log(level, fmt.Sprintf(format, args...))
	}
}

// listRuns 返回按 Started 倒序排列的 Run 快照；无 Run 时返回空切片（JSON 为 []）。
func (m *captureModule) listRuns() []runView {
	m.mu.Lock()
	items := make([]runView, 0, len(m.runs))
	for _, r := range m.runs {
		items = append(items, runViewOf(r))
	}
	m.mu.Unlock()

	sort.Slice(items, func(i, j int) bool {
		if items[i].Started.Equal(items[j].Started) {
			return items[i].ID > items[j].ID
		}
		return items[i].Started.After(items[j].Started)
	})
	return items
}

// getRun 返回单个 Run 的快照。
func (m *captureModule) getRun(id string) (runView, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.runs[id]
	if r == nil {
		return runView{}, false
	}
	return runViewOf(r), true
}

// stopRun 停止指定 Run（取消 ctx 并等待退出），幂等。
//
// 若 Run 仍在运行则置为 done；已 done/error 的不覆盖其状态。
func (m *captureModule) stopRun(id string) (runView, bool) {
	m.mu.Lock()
	r := m.runs[id]
	if r == nil {
		m.mu.Unlock()
		return runView{}, false
	}
	cancel := r.cancel
	done := r.done
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	select {
	case <-done:
	case <-time.After(stopRunWait):
		m.logf("warn", "capture: 等待 Run %s 停止超时", id)
	}

	m.mu.Lock()
	if r.State == runStateRunning {
		r.State = runStateDone
		r.Finished = time.Now()
	}
	v := runViewOf(r)
	m.mu.Unlock()
	return v, true
}

// getDataDir 返回宿主下发（或测试注入）的抓包文件目录。
func (m *captureModule) getDataDir() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dataDir
}
