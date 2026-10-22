package alerting

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"

	"flow-monitoring/internal/kernel/eventbus"
)

// DefaultPushBuffer 是 OnAlert 派发通道的默认缓冲容量（Config.PushBuffer <= 0 时使用）。
//
// ★ 必须是有界缓冲：WS 广播是同步遍历所有连接逐个 Send，慢客户端会阻塞调用方，
//
//	所以告警消费循环只能"投递到通道就返回"，缓冲满时丢弃并计数，绝不反压消费。
const DefaultPushBuffer = 256

// Config 是 alerting 服务的装配配置。
type Config struct {
	// Capacity 是环形缓冲容量（沿用 config.Detect.AlertBuffer；<=0 用默认值）。
	Capacity int
	// Logger 可选：nil 时退回 slog.Default()（解析失败的日志不能静默丢）。
	Logger *slog.Logger
	// PushBuffer 是 OnAlert 派发通道的缓冲容量（<=0 用 DefaultPushBuffer）。
	PushBuffer int
	// RestorePath 是启动时回填告警的 JSONL 归档路径（空 = 不回填）。
	// ★ 与 alert 模块的 alert.sink_path 指向同一文件；不存在时静默跳过。
	RestorePath string
}

// Stats 是 /api/alerts/stats 的响应体。
//
// ★ 15-2b 起宿主不再加载规则、也不再跑回放：rules_total / rules_by_source /
// replay 这些它不知道的信息被移除，留着就是撒谎。
type Stats struct {
	Enabled     bool   `json:"enabled"`
	AlertsTotal int    `json:"alerts_total"`
	Capacity    int    `json:"capacity"`
	Received    uint64 `json:"received"`
	Dropped     uint64 `json:"dropped"`
	// PushDropped 是 OnAlert 派发通道满时丢弃的条数（有界缓冲，绝不反压消费）。
	PushDropped  uint64 `json:"push_dropped"`
	DecodeErrors uint64 `json:"decode_errors"`
	LastError    string `json:"last_error"`

	// ByMode / ByRun 是环形缓冲里按 mode / run_id 分组的条数（空值不计）。
	// 始终非 nil（空缓冲为 {}），避免 JSON 序列化成 null。
	ByMode map[string]int `json:"by_mode"`
	ByRun  map[string]int `json:"by_run"`

	// Restored 是启动时从 JSONL 归档回填的告警条数（不计入 Received）。
	Restored int `json:"restored"`
}

// Service 只订阅 detect.feature 事件并缓存告警，不加载规则、不跑热路径。
type Service struct {
	ring   *ring
	logger *slog.Logger
	// pushBuf 是 OnAlert 派发通道的容量（构造后不变）。
	pushBuf int

	mu        sync.Mutex
	enabled   bool
	sub       *eventbus.Subscription
	bus       *eventbus.Bus
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	received  uint64
	decodeErr uint64
	lastError string
	// restored 是启动时从 JSONL 归档回填的条数（受 mu 保护）。
	restored int
	// onAlert 是分配 id 并写入环形缓冲后回调的钩子（可为 nil）。
	onAlert func(Alert)
	// pushCh 是有界派发通道；只由 consume goroutine 投递、dispatch goroutine 消费。
	pushCh chan Alert
	// pushDropped 是派发通道满时丢弃的条数（受 mu 保护）。
	pushDropped uint64
}

// New 创建 alerting 服务（只装配环形缓冲与日志器，不启动订阅）。
//
// ★ RestorePath 非空时在此处同步回填历史告警（任务 18b）：回填失败只记日志、
//
//	绝不阻断启动；文件不存在视为首次运行，静默跳过。
func New(cfg Config) *Service {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	pushBuf := cfg.PushBuffer
	if pushBuf <= 0 {
		pushBuf = DefaultPushBuffer
	}
	s := &Service{
		ring:    newRing(cfg.Capacity),
		logger:  logger,
		pushBuf: pushBuf,
	}
	if cfg.RestorePath != "" {
		n, err := s.RestoreFromFile(cfg.RestorePath)
		switch {
		case err != nil:
			logger.Warn("alerting: 回填告警归档失败（忽略，继续启动）",
				"path", cfg.RestorePath, "err", err)
		case n > 0:
			logger.Info("alerting: 已从告警归档回填",
				"path", cfg.RestorePath, "restored", n)
		}
	}
	return s
}

// RestoreFromFile 从 JSONL 归档回填环形缓冲（只保留最后 len(capacity) 条）。
//
// 语义：
//   - 文件不存在 ⇒ (0, nil)，不报错（首次运行没有归档）；
//   - 逐行读取，用滑动窗口只保留最后 capacity 条，不一次性把整个文件读进内存；
//   - 每行二次解析：先把 alert 解成 json.RawMessage，再解成宿主 DTO（不 import detect）；
//   - 任何解析失败都只记日志并跳过该行，不影响启动；
//   - 回填后按 time 升序写入，id 由 ring.add 从 1 连续分配（与运行期一致）；
//   - 不发 OnAlert 回调、不计入 Received；回填条数记入 Stats().Restored。
func (s *Service) RestoreFromFile(path string) (restored int, err error) {
	if s == nil || path == "" {
		return 0, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	capacity := s.ring.capacity()
	rows := make([]Alert, 0, capacity)

	sc := bufio.NewScanner(f)
	// 单行可能较长（snippet 等），放宽扫描缓冲上限。
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var row struct {
			CaptureID string          `json:"capture_id"`
			RunID     string          `json:"run_id"`
			Mode      string          `json:"mode"`
			Alert     json.RawMessage `json:"alert"`
		}
		if uerr := json.Unmarshal(line, &row); uerr != nil {
			s.warnRestoreSkip(path, uerr)
			continue
		}
		a, ok := decodeRestoredAlert(row.Alert)
		if !ok {
			s.warnRestoreSkip(path, fmt.Errorf("alert 字段不是合法对象"))
			continue
		}
		a.RunID = row.RunID
		a.Mode = row.Mode
		a.CaptureID = row.CaptureID

		// 滑动窗口：只保留最后 capacity 条。
		if len(rows) >= capacity {
			copy(rows, rows[1:])
			rows = rows[:capacity-1]
		}
		rows = append(rows, a)
	}
	if serr := sc.Err(); serr != nil {
		return 0, fmt.Errorf("alerting: 读取归档 %s: %w", path, serr)
	}

	// 按 time 升序回填（同时间保持文件顺序，稳定排序）。
	sort.SliceStable(rows, func(i, j int) bool {
		return restoreTimeLess(rows[i].Time, rows[j].Time)
	})
	for _, a := range rows {
		s.ring.add(a)
		restored++
	}
	if restored > 0 {
		s.mu.Lock()
		s.restored += restored
		s.mu.Unlock()
	}
	return restored, nil
}

// restoreAlertPascal 与 detect.Alert 的 JSON 形状（Go 字段名，PascalCase）对齐。
//
// ★ 内核不能 import detect，因此这里用一份纯数据镜像做二次解析；它只服务回填，
//
//	不参与任何对外 API（对外仍是 dto.go 里的 Alert）。
type restoreAlertPascal struct {
	RuleID   string
	Name     string
	Severity string
	Weight   int
	Time     string
	SrcIP    string
	SrcPort  uint16
	DstIP    string
	DstPort  uint16
	Proto    string
	StreamID int
	PktNo    int
	Buffer   string
	Offset   int
	Snippet  string
}

func (p restoreAlertPascal) toAlert() Alert {
	return Alert{
		RuleID:   p.RuleID,
		Name:     p.Name,
		Severity: p.Severity,
		Weight:   p.Weight,
		Time:     p.Time,
		SrcIP:    p.SrcIP,
		SrcPort:  p.SrcPort,
		DstIP:    p.DstIP,
		DstPort:  p.DstPort,
		Proto:    p.Proto,
		StreamID: p.StreamID,
		PktNo:    p.PktNo,
		Buffer:   p.Buffer,
		Offset:   p.Offset,
		Snippet:  p.Snippet,
	}
}

// decodeRestoredAlert 兼容两种 alert 键名形状：
//   - 宿主 DTO 的 snake_case（json.Marshal(Alert) 的产物，含手工/测试输入）；
//   - detect.Alert 的 PascalCase（data/alerts.jsonl 的真实形状：Alert 无 json tag）。
//
// ★ 直接 import detect 会破坏内核纯净性（purity_test.go 会红），所以两种形状
//
//	各解一次再择优；RuleID 非空者优先。
func decodeRestoredAlert(raw json.RawMessage) (Alert, bool) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return Alert{}, false
	}

	var snake Alert
	snakeErr := json.Unmarshal(raw, &snake)
	if snakeErr == nil && snake.RuleID != "" {
		return snake, true
	}

	var pascal restoreAlertPascal
	pascalErr := json.Unmarshal(raw, &pascal)
	if pascalErr == nil && pascal.RuleID != "" {
		return pascal.toAlert(), true
	}

	if snakeErr != nil && pascalErr != nil {
		return Alert{}, false
	}
	// 合法 JSON 但没有可识别的 RuleID：保留 snake 解出的字段（与旧行为一致）。
	return snake, true
}

// restoreTimeLess 按 RFC3339 时间比较；解析失败时退回字符串比较。
func restoreTimeLess(a, b string) bool {
	ta, ea := time.Parse(time.RFC3339, a)
	tb, eb := time.Parse(time.RFC3339, b)
	if ea == nil && eb == nil {
		return ta.Before(tb)
	}
	return a < b
}

// warnRestoreSkip 记录被跳过的坏行（不影响启动）。
func (s *Service) warnRestoreSkip(path string, err error) {
	if s.logger != nil {
		s.logger.Warn("alerting: 跳过无法解析的回填行", "path", path, "err", err)
	}
}

// SetOnAlert 注册告警回调：每条告警分配 id 并写入环形缓冲后调用。
//
// ★ 回调在独立 goroutine 里执行（经有界缓冲派发），不会阻塞事件消费循环；
//
//	缓冲满时丢弃并计入 Stats().PushDropped。传 nil 可关闭推送。
func (s *Service) SetOnAlert(fn func(Alert)) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.onAlert = fn
	s.mu.Unlock()
}

// Start 订阅 topic 并在后台 goroutine 里消费事件。
//
// 幂等：已在运行时再调用是 no-op。订阅缓冲取 ring 容量，突发时不轻易丢事件。
func (s *Service) Start(bus *eventbus.Bus, topic string) {
	if s == nil || bus == nil || topic == "" {
		return
	}

	s.mu.Lock()
	if s.cancel != nil { // 已经在运行
		s.mu.Unlock()
		return
	}
	buf := s.ring.capacity()
	sub := bus.Subscribe(topic, buf)
	ctx, cancel := context.WithCancel(context.Background())
	s.sub = sub
	s.bus = bus
	s.cancel = cancel
	s.enabled = true
	// 每次启动都重建派发通道，避免上次运行残留的告警被再次派发。
	s.pushCh = make(chan Alert, s.pushBuf)
	// ★ 在持锁时 Add，保证 Stop 的 Wait 不会与 Add 竞态。
	s.wg.Add(2)
	s.mu.Unlock()

	go s.consume(ctx, sub)
	go s.dispatch(ctx, s.pushCh)
}

// Stop 取消消费 goroutine 并退订；幂等。
func (s *Service) Stop() {
	if s == nil {
		return
	}

	s.mu.Lock()
	cancel := s.cancel
	sub := s.sub
	bus := s.bus
	s.cancel = nil
	s.sub = nil
	s.bus = nil
	s.mu.Unlock()

	if cancel == nil { // 已停止
		return
	}
	cancel()
	s.wg.Wait()
	// 成对调用：订阅的 channel 必须显式关闭，避免订阅表泄漏。
	if bus != nil && sub != nil {
		bus.Unsubscribe(sub)
	}
}

// Query 按 id 升序返回一页告警（可选按 mode/run_id/capture_id 过滤，见 ring.query）。
func (s *Service) Query(page, pageSize int, sinceID uint64, f Filter) Page {
	if s == nil {
		return Page{Items: []Alert{}, Page: 1, PageSize: DefaultPageSize}
	}
	return s.ring.query(page, pageSize, sinceID, f)
}

// Stats 返回当前状态快照（并发安全）。
func (s *Service) Stats() Stats {
	if s == nil {
		return Stats{ByMode: map[string]int{}, ByRun: map[string]int{}}
	}

	s.mu.Lock()
	enabled := s.enabled
	received := s.received
	decodeErr := s.decodeErr
	lastError := s.lastError
	pushDropped := s.pushDropped
	restored := s.restored
	s.mu.Unlock()

	byMode, byRun := s.ring.groupCounts()

	return Stats{
		Enabled:      enabled,
		AlertsTotal:  s.ring.len(),
		Capacity:     s.ring.capacity(),
		Received:     received,
		Dropped:      s.ring.droppedCount(),
		PushDropped:  pushDropped,
		DecodeErrors: decodeErr,
		LastError:    lastError,
		ByMode:       byMode,
		ByRun:        byRun,
		Restored:     restored,
	}
}

// consume 从订阅 channel 读事件直到被取消或 channel 关闭。
func (s *Service) consume(ctx context.Context, sub *eventbus.Subscription) {
	defer s.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-sub.C():
			if !ok {
				return
			}
			s.handle(ev)
		}
	}
}

// handle 处理一条事件：类型断言字节 → json.Unmarshal → 进环形缓冲。
//
// 解析失败计数 + 打日志，绝不静默丢弃（技术债 #2 的同类问题）。
func (s *Service) handle(ev eventbus.Event) {
	raw, ok := payloadBytes(ev.Payload)
	if !ok {
		// ★ received 与 decodeErr 必须成对、在同一临界区内更新，
		//   否则 Stats() 可能读到 "received=1 但 decodeErrors=0" 的撕裂快照
		//   （曾导致 TestServiceDecodeErrorCounted 等测试偶发失败）。
		s.recordDecodeError(fmt.Errorf("alerting: 事件载荷类型 %T 不是字节（期望 []byte / json.RawMessage）", ev.Payload))
		return
	}

	var a Alert
	if err := json.Unmarshal(raw, &a); err != nil {
		s.recordDecodeError(fmt.Errorf("alerting: 解析 detect.feature 告警失败: %w", err))
		return
	}

	s.mu.Lock()
	s.received++
	s.mu.Unlock()
	rec := s.ring.add(a)
	s.push(rec)
}

// push 把一条已入库的告警非阻塞地投递到派发通道。
//
// ★ 缓冲满时丢弃并计数，绝不阻塞调用方（consume 循环）；没有回调时直接跳过。
func (s *Service) push(a Alert) {
	s.mu.Lock()
	hasSink := s.onAlert != nil
	s.mu.Unlock()
	if !hasSink {
		return
	}
	select {
	case s.pushCh <- a:
	default:
		s.mu.Lock()
		s.pushDropped++
		s.mu.Unlock()
	}
}

// dispatch 在独立 goroutine 里消费派发通道并调用 OnAlert。
//
// 慢客户端（BroadcastJSON 同步 Send）只会阻塞这里，不会反压 consume 循环。
func (s *Service) dispatch(ctx context.Context, ch <-chan Alert) {
	defer s.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case a := <-ch:
			s.mu.Lock()
			fn := s.onAlert
			s.mu.Unlock()
			if fn != nil {
				fn(a)
			}
		}
	}
}

// payloadBytes 把事件载荷统一成字节。
//
// ★ 进程内测试直接 Publish([]byte)，跨进程桥接（pluginhost.Bridge.Publish）
//
//	用的是 json.RawMessage(data)——两者底层都是字节，必须都认，否则真实链路会全挂着。
func payloadBytes(p any) ([]byte, bool) {
	switch v := p.(type) {
	case []byte:
		return v, true
	case json.RawMessage:
		return []byte(v), true
	case string:
		return []byte(v), true
	default:
		return nil, false
	}
}

// recordDecodeError 累计解析失败并记录最近一次错误 + 打日志。
func (s *Service) recordDecodeError(err error) {
	msg := err.Error()
	s.mu.Lock()
	// ★ 与 received 在同一临界区递增，保证 Stats() 的快照自洽。
	s.received++
	s.decodeErr++
	s.lastError = msg
	s.mu.Unlock()

	if s.logger != nil {
		s.logger.Warn("alerting: 丢弃无法解析的事件", "err", msg)
	}
}
