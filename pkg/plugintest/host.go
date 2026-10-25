// Package plugintest 提供 plugin.Host 的内存假实现，供各模块的测试复用。
//
// 它不是生产代码：生产模块不会 import 本包，只在 _test.go 中使用。
// 设计目标：
//   - 一次实现 plugin.Host 的全部方法，避免每个测试文件重复写 20+ 个空方法；
//   - 记录 Log / Publish 调用，测试可断言模块的对外行为；
//   - 用 PollFunc 脚本化 Poll 返回值（默认从内存事件表增量取）；
//   - RunHost 在 Host 基础上**额外**实现 plugin.RunStore，
//     而 Host 本身不实现 RunStore，从而仍能测试"宿主不支持持久化"的分支。
package plugintest

import (
	"strings"
	"sync"
	"time"

	"flow-monitoring/pkg/plugin"
)

// LogLine 是一次 Host.Log 调用的记录。
type LogLine struct {
	Level string
	Msg   string
}

// PublishedEvent 是一次 Host.Publish 调用的记录。
type PublishedEvent struct {
	Topic string
	Data  []byte
}

// PollCall 是一次 Host.Poll 调用的参数记录。
type PollCall struct {
	Topic string
	Since uint64
	Max   int
}

// Host 是 plugin.Host 的内存假实现（测试用）。
//
// 可直接注入的字段：
//   - Cfg：Config() 的返回值
//   - PollFunc：非空时 Poll 直接委托给它（可脚本化返回/panic）
//   - Captures / Packets：预置存储数据（CaptureGet 等查询命中）
//
// Logs / Published 由 Host 自己追加，测试应通过 Snapshot、
// PublishedTo、LogsWithLevel 等方法读取，避免与后台 goroutine 竞争。
type Host struct {
	Cfg      plugin.ConfigSnapshot
	PollFunc func(topic string, since uint64, max int) []plugin.EventRecord

	// 可预置的内存存储（键为 capture ID）。
	Captures map[string]plugin.CaptureRecord
	Packets  map[string][]plugin.PacketRecord

	// 调用记录（由 Host 维护）。
	Logs      []LogLine
	Published []PublishedEvent

	mu       sync.Mutex
	pollCall []PollCall
	events   map[string][]plugin.EventRecord

	httpBases map[string]string
	services  map[string]plugin.ServiceRef
}

var _ plugin.Host = (*Host)(nil)

// New 返回一个空的假宿主。
func New() *Host {
	return &Host{
		Captures:  make(map[string]plugin.CaptureRecord),
		Packets:   make(map[string][]plugin.PacketRecord),
		events:    make(map[string][]plugin.EventRecord),
		httpBases: make(map[string]string),
		services:  make(map[string]plugin.ServiceRef),
	}
}

// Append 往内存事件表追加一条事件（模拟宿主 EventLog）。
//
// Poll 默认按 Seq>since 过滤并按 max 截断返回这些事件。
func (h *Host) Append(topic string, seq uint64, data []byte) {
	cp := append([]byte(nil), data...)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.events == nil {
		h.events = make(map[string][]plugin.EventRecord)
	}
	h.events[topic] = append(h.events[topic], plugin.EventRecord{
		Topic: topic,
		Seq:   seq,
		Data:  cp,
		Time:  time.Unix(int64(seq), 0),
	})
}

// PollCalls 返回截至当前的所有 Poll 调用参数副本。
func (h *Host) PollCalls() []PollCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]PollCall(nil), h.pollCall...)
}

// Snapshot 返回 Publish 与 Log 记录的副本（并发安全）。
func (h *Host) Snapshot() ([]PublishedEvent, []LogLine) {
	h.mu.Lock()
	defer h.mu.Unlock()
	pubs := make([]PublishedEvent, len(h.Published))
	for i, p := range h.Published {
		pubs[i] = PublishedEvent{Topic: p.Topic, Data: append([]byte(nil), p.Data...)}
	}
	logs := append([]LogLine(nil), h.Logs...)
	return pubs, logs
}

// PublishedTo 返回某主题下所有 Publish 载荷的副本。
func (h *Host) PublishedTo(topic string) [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out [][]byte
	for _, p := range h.Published {
		if p.Topic == topic {
			out = append(out, append([]byte(nil), p.Data...))
		}
	}
	return out
}

// LogsWithLevel 返回指定级别的日志副本。
func (h *Host) LogsWithLevel(level string) []LogLine {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []LogLine
	for _, l := range h.Logs {
		if l.Level == level {
			out = append(out, l)
		}
	}
	return out
}

// LogText 返回所有日志的 "level|msg" 行，以换行拼接。
func (h *Host) LogText() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	lines := make([]string, len(h.Logs))
	for i, l := range h.Logs {
		lines[i] = l.Level + "|" + l.Msg
	}
	return strings.Join(lines, "\n")
}

// HasLog 报告是否已有包含 substr 的日志。
func (h *Host) HasLog(substr string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, l := range h.Logs {
		if strings.Contains(l.Msg, substr) {
			return true
		}
	}
	return false
}

// WaitLog 轮询等待出现包含 substr 的日志，超时返回 false。
func (h *Host) WaitLog(substr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if h.HasLog(substr) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// Config 实现 plugin.Host。
func (h *Host) Config() plugin.ConfigSnapshot { return h.Cfg }

// Log 实现 plugin.Host：只记录，不报错。
func (h *Host) Log(level, msg string) {
	h.mu.Lock()
	h.Logs = append(h.Logs, LogLine{Level: level, Msg: msg})
	h.mu.Unlock()
}

// Publish 实现 plugin.Host：只记录载荷副本，不报错。
func (h *Host) Publish(topic string, data []byte) error {
	cp := append([]byte(nil), data...)
	h.mu.Lock()
	h.Published = append(h.Published, PublishedEvent{Topic: topic, Data: cp})
	h.mu.Unlock()
	return nil
}

// Poll 实现 plugin.Host：优先委托 PollFunc，否则从内存事件表增量读取。
func (h *Host) Poll(topic string, since uint64, max int) []plugin.EventRecord {
	h.mu.Lock()
	h.pollCall = append(h.pollCall, PollCall{Topic: topic, Since: since, Max: max})
	fn := h.PollFunc
	src := append([]plugin.EventRecord(nil), h.events[topic]...)
	h.mu.Unlock()

	if fn != nil {
		return fn(topic, since, max)
	}
	if max <= 0 {
		max = 100
	}
	var out []plugin.EventRecord
	for _, ev := range src {
		if ev.Seq > since {
			out = append(out, ev)
			if len(out) >= max {
				break
			}
		}
	}
	return out
}

// RegisterHTTP 实现 plugin.Host：记录上报地址。
func (h *Host) RegisterHTTP(httpBase, addr, moduleID string) error {
	h.mu.Lock()
	if h.httpBases == nil {
		h.httpBases = make(map[string]string)
	}
	h.httpBases[moduleID] = httpBase + addr
	h.mu.Unlock()
	return nil
}

// RegisterService 实现 plugin.Host：内存登记服务引用。
func (h *Host) RegisterService(ref plugin.ServiceRef) error {
	h.mu.Lock()
	if h.services == nil {
		h.services = make(map[string]plugin.ServiceRef)
	}
	h.services[ref.Name] = ref
	h.mu.Unlock()
	return nil
}

// LookupService 实现 plugin.Host：查不到返回 false。
func (h *Host) LookupService(name string) (plugin.ServiceRef, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ref, ok := h.services[name]
	return ref, ok
}

// UnregisterService 实现 plugin.Host：幂等删除。
func (h *Host) UnregisterService(name string) error {
	h.mu.Lock()
	delete(h.services, name)
	h.mu.Unlock()
	return nil
}

// CaptureCreate 实现 plugin.Host：写入内存表。
func (h *Host) CaptureCreate(rec plugin.CaptureRecord) error {
	h.mu.Lock()
	if h.Captures == nil {
		h.Captures = make(map[string]plugin.CaptureRecord)
	}
	h.Captures[rec.ID] = rec
	h.mu.Unlock()
	return nil
}

// CaptureGet 实现 plugin.Host：查不到返回 false。
func (h *Host) CaptureGet(id string) (plugin.CaptureRecord, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	rec, ok := h.Captures[id]
	return rec, ok
}

// CaptureList 实现 plugin.Host：按 Offset/Limit 分页返回内存表。
func (h *Host) CaptureList(page plugin.Page) plugin.CapturePage {
	h.mu.Lock()
	defer h.mu.Unlock()
	items := make([]plugin.CaptureRecord, 0, len(h.Captures))
	for _, rec := range h.Captures {
		items = append(items, rec)
	}
	total := len(items)
	items = pageSlice(items, page)
	return plugin.CapturePage{Items: items, Total: total}
}

// CaptureDelete 实现 plugin.Host：幂等删除。
func (h *Host) CaptureDelete(id string) error {
	h.mu.Lock()
	delete(h.Captures, id)
	h.mu.Unlock()
	return nil
}

// PacketSaveBatch 实现 plugin.Host：追加写入内存表。
func (h *Host) PacketSaveBatch(captureID string, packets []plugin.PacketRecord) error {
	h.mu.Lock()
	if h.Packets == nil {
		h.Packets = make(map[string][]plugin.PacketRecord)
	}
	h.Packets[captureID] = append(h.Packets[captureID], packets...)
	h.mu.Unlock()
	return nil
}

// PacketList 实现 plugin.Host：按 Offset/Limit 分页返回内存表。
func (h *Host) PacketList(captureID string, page plugin.Page) plugin.PacketPage {
	h.mu.Lock()
	defer h.mu.Unlock()
	items := append([]plugin.PacketRecord(nil), h.Packets[captureID]...)
	total := len(items)
	items = pageSlice(items, page)
	return plugin.PacketPage{Items: items, Total: total}
}

// PacketCount 实现 plugin.Host：返回该抓包的内存包数。
func (h *Host) PacketCount(captureID string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.Packets[captureID])
}

// PacketDelete 实现 plugin.Host：幂等删除。
func (h *Host) PacketDelete(captureID string) error {
	h.mu.Lock()
	delete(h.Packets, captureID)
	h.mu.Unlock()
	return nil
}

// RunHost 在 Host 基础上额外实现 plugin.RunStore。
//
// ★ 必须与 Host 分开：Host 不实现 RunStore，才能测试模块
// "宿主不支持 Run 持久化" 的分支；RunHost 用于测试支持持久化的分支。
type RunHost struct {
	*Host

	SavedRuns []plugin.RunRecord

	restore []plugin.RunRecord
	runMu   sync.Mutex
}

var _ plugin.RunStore = (*RunHost)(nil)

// NewRunHost 返回一个支持 Run 持久化的假宿主。
// restore 为 RunList 预置的历史记录。
func NewRunHost(restore ...plugin.RunRecord) *RunHost {
	return &RunHost{
		Host:    New(),
		restore: append([]plugin.RunRecord(nil), restore...),
	}
}

// RunSave 实现 plugin.RunStore：按调用顺序记录每次保存。
func (h *RunHost) RunSave(rec plugin.RunRecord) error {
	h.runMu.Lock()
	h.SavedRuns = append(h.SavedRuns, rec)
	h.runMu.Unlock()
	return nil
}

// RunList 实现 plugin.RunStore：返回预置历史（可被 limit 截断）。
func (h *RunHost) RunList(limit int) []plugin.RunRecord {
	h.runMu.Lock()
	defer h.runMu.Unlock()
	out := append([]plugin.RunRecord(nil), h.restore...)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Saved 返回已保存 Run 记录的副本（并发安全）。
func (h *RunHost) Saved() []plugin.RunRecord {
	h.runMu.Lock()
	defer h.runMu.Unlock()
	return append([]plugin.RunRecord(nil), h.SavedRuns...)
}

// pageSlice 对任意切片应用 Offset/Limit（越界安全）。
func pageSlice[T any](items []T, page plugin.Page) []T {
	start := page.Offset
	if start < 0 {
		start = 0
	}
	if start > len(items) {
		start = len(items)
	}
	end := len(items)
	if page.Limit > 0 && start+page.Limit < end {
		end = start + page.Limit
	}
	return items[start:end]
}
