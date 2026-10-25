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
	"flow-monitoring/internal/kernel/storage"
)

// DefaultPushBuffer 是 OnAlert 派发通道的默认缓冲容量（Config.PushBuffer <= 0 时使用）。
//
// ★ 必须是有界缓冲：WS 广播是同步遍历所有连接逐个 Send，慢客户端会阻塞调用方，
//
//	所以告警消费循环只能"投递到通道就返回"，缓冲满时丢弃并计数，绝不反压消费。
const DefaultPushBuffer = 256

// 告警批量落库参数（任务 C1）。
const (
	// persistQueueSize 是待写队列（有界通道）容量。
	// ★ 队列满时 enqueue 阻塞（反压到事件消费循环）：宁可慢，不可丢。
	persistQueueSize = 4096
	// flushBatchSize 是单个 INSERT 批次上限（满则立即刷）。
	flushBatchSize = 200
	// flushInterval 是"攒批"最长等待时间（先到者：满 200 条或满 100ms）。
	flushInterval = 100 * time.Millisecond
	// persistRetryDelay 是批次写入失败后的重试间隔。
	persistRetryDelay = 50 * time.Millisecond
)

// AlertQuery 是查库查询条件（Store != nil 时 /api/alerts 走这里）。
//
// ★ 空字符串表示"不按该字段过滤"；SinceID>0 表示只取 id > SinceID 的记录。
type AlertQuery struct {
	Page      int
	PageSize  int
	SinceID   uint64
	Mode      string
	RunID     string
	CaptureID string
}

// AlertStore 是 alerting 的**可选持久化能力**（由 internal/modules/store.Postgres 实现）。
//
// ★ 接口定义在消费者侧：alerting 只依赖这个最小契约，绝不 import internal/modules/**，
//
//	保持内核纯净性（purity_test.go）。Store == nil 或实现不满足该接口时退回内存模式。
//
// ★ 为什么以 DB 的 BIGSERIAL 为唯一 ID：内存自增 ID 与库 ID 必须二选一，否则前端
//
//	since_id 增量会错乱。InsertAlerts 返回的 id 会被回填到 Alert 后再进环形缓冲。
type AlertStore interface {
	// InsertAlerts 批量插入告警，按输入顺序返回库分配的 id。
	// ★ 必须是单条原子 INSERT（失败则一行都没插入），这样上层重试不会重复插入。
	InsertAlerts(ctx context.Context, alerts []Alert) ([]uint64, error)
	// QueryAlerts 按过滤条件分页查询（ORDER BY id ASC），返回 items 与过滤后总数。
	QueryAlerts(ctx context.Context, q AlertQuery) ([]Alert, int, error)
}

// Config 是 alerting 服务的装配配置。
type Config struct {
	// Capacity 是环形缓冲容量（沿用 config.Detect.AlertBuffer；<=0 用默认值）。
	Capacity int
	// Logger 可选：nil 时退回 slog.Default()（解析失败的日志不能静默丢）。
	Logger *slog.Logger
	// PushBuffer 是 OnAlert 派发通道的缓冲容量（<=0 用 DefaultPushBuffer）。
	PushBuffer int
	// Store 是进程内存储聚合接口（nil 表示不持久化，退回纯内存模式）。
	// ★ 只依赖 internal/kernel/storage.Storage 接口；实际告警读写能力经 AlertStore 探测。
	Store storage.Storage
	// RestorePath 是启动时回填告警的 JSONL 归档路径（空 = 不回填）。
	// ★ 与 alert 模块的 alert.sink_path 指向同一文件；不存在时静默跳过。
	// ★ 有库（Store != nil）时应留空：历史由库恢复，避免内存自增 id 与库 id 冲突。
	RestorePath string
}

// Stats 是 /api/alerts/stats 的响应体。
//
// ★ 15-2b 起宿主不再加载规则、也不再跑回放：rules_total / rules_by_source /
// replay 这些它不知道的信息被移除，留着就是撒谎。
type Stats struct {
	Enabled     bool `json:"enabled"`
	AlertsTotal int  `json:"alerts_total"`
	// BufferTotal 是环形缓冲（热层）里的条数；有库时 AlertsTotal 报的是库总数。
	BufferTotal int    `json:"buffer_total"`
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

	// Persisted 是成功写入 PG 的告警条数（C1）。
	Persisted uint64 `json:"persisted"`
	// PersistErrors 是批量写入失败（含重试）的累计次数。
	PersistErrors uint64 `json:"persist_errors"`
	// Pending 是待写队列当前积压条数（不含正在写的那一批）。
	Pending int `json:"pending"`
	// PersistBackpressure 是待写队列满、消费循环被迫阻塞的累计次数。
	PersistBackpressure uint64 `json:"persist_backpressure"`
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

	// —— 任务 C1：批量落库 ——
	// alertStore 是告警持久化能力（nil ⇒ 纯内存模式；构造后不变）。
	alertStore AlertStore
	// persistCh 是有界待写队列；enqueue 满时阻塞，persistLoop 消费。
	persistCh chan Alert
	// persistQuit 关闭后 persistLoop 排空剩余队列并退出。
	persistQuit chan struct{}
	// persistStopOnce 保证 persistQuit 只关闭一次（Stop 幂等）。
	persistStopOnce sync.Once
	persistWG       sync.WaitGroup
	// persisted / persistErrors / backpressure 受 mu 保护。
	persisted     uint64
	persistErrors uint64
	backpressure  uint64
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
	// C1：探测存储是否提供告警持久化能力（nil / 不支持 ⇒ 纯内存模式，向后兼容）。
	if cfg.Store != nil {
		if as, ok := cfg.Store.(AlertStore); ok {
			s.alertStore = as
		} else {
			logger.Warn("alerting: 存储实现未提供告警持久化能力，退回内存模式")
		}
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
	// 有库时启动后台批量落库 goroutine（Stop 会排空剩余队列再退出）。
	if s.alertStore != nil {
		s.startPersist()
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

	if cancel != nil {
		cancel()
		// ★ 先等消费 goroutine 退出（不再 enqueue），再停落库 goroutine：
		//   排空期间不会再有新的入队者，避免 send-on-closed / 丢数据。
		s.wg.Wait()
		// 成对调用：订阅的 channel 必须显式关闭，避免订阅表泄漏。
		if bus != nil && sub != nil {
			bus.Unsubscribe(sub)
		}
	}
	// C1：停止批量落库 goroutine（排空剩余队列后再退出，幂等）。
	s.stopPersist()
}

// Query 按 id 升序返回一页告警（可选按 mode/run_id/capture_id 过滤）。
//
// ★ Store != nil ⇒ 查库（全量历史，不受环形缓冲容量限制）；
//
//	Store == nil ⇒ 退回查环形缓冲（保持现有测试与无库场景可用）。
func (s *Service) Query(page, pageSize int, sinceID uint64, f Filter) Page {
	if s == nil {
		return Page{Items: []Alert{}, Page: 1, PageSize: DefaultPageSize}
	}
	if s.alertStore != nil {
		return s.queryStore(page, pageSize, sinceID, f)
	}
	return s.ring.query(page, pageSize, sinceID, f)
}

// queryStore 走库查询（Store != nil 时 /api/alerts 的唯一路径）。
//
// ★ 分页语义与 ring.query 保持一致：page>=1、pageSize 默认 50 上限 500、
// items 空时必须是 []（不是 nil）、total 为过滤后总数（不是全表行数）。
// ★ 查库出错时记 last_error 并返回空页（HTTP 层仍 200 + 空列表，不白屏）。
func (s *Service) queryStore(page, pageSize int, sinceID uint64, f Filter) Page {
	page, pageSize = normalizePage(page, pageSize)
	items, total, err := s.alertStore.QueryAlerts(context.Background(), AlertQuery{
		Page:      page,
		PageSize:  pageSize,
		SinceID:   sinceID,
		Mode:      f.Mode,
		RunID:     f.RunID,
		CaptureID: f.CaptureID,
	})
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("alerting: 查库失败，返回空页", "err", err)
		}
		s.mu.Lock()
		s.lastError = err.Error()
		s.mu.Unlock()
		return Page{Items: []Alert{}, Page: page, PageSize: pageSize, Total: 0}
	}
	if items == nil {
		items = []Alert{}
	}
	return Page{Items: items, Page: page, PageSize: pageSize, Total: total}
}

// normalizePage 归一化分页参数（ring 与 store 两条查询路径共用同一套语义）。
func normalizePage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}
	return page, pageSize
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
	persisted := s.persisted
	persistErrors := s.persistErrors
	backpressure := s.backpressure
	s.mu.Unlock()

	byMode, byRun := s.ring.groupCounts()

	// 待写队列积压（不含正在写的那一批）；内存模式下为 0。
	var pending int
	if s.persistCh != nil {
		pending = len(s.persistCh)
	}

	// ★ 有库时 AlertsTotal 报"库里的总数"（与 /api/alerts 的 total 一致），
	//   缓冲条数单独用 BufferTotal 报 —— 否则 stats 与列表会给出两个不同的数。
	bufferTotal := s.ring.len()
	alertsTotal := bufferTotal
	if s.alertStore != nil {
		alertsTotal = s.Query(1, 1, 0, Filter{}).Total
	}

	return Stats{
		Enabled:             enabled,
		AlertsTotal:         alertsTotal,
		BufferTotal:         bufferTotal,
		Capacity:            s.ring.capacity(),
		Received:            received,
		Dropped:             s.ring.droppedCount(),
		PushDropped:         pushDropped,
		DecodeErrors:        decodeErr,
		LastError:           lastError,
		ByMode:              byMode,
		ByRun:               byRun,
		Restored:            restored,
		Persisted:           persisted,
		PersistErrors:       persistErrors,
		Pending:             pending,
		PersistBackpressure: backpressure,
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

	// 有库：投递到待写队列（后台批量落库，回填 DB 分配的 id 后再进环形缓冲）。
	if s.alertStore != nil {
		s.enqueue(a)
		return
	}
	// 无库：保持旧行为（内存自增 id + 立即进环形缓冲）。
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

// —— 任务 C1：批量落库 ——
//
// 设计要点：
//   - 待写队列是有界通道（persistQueueSize），满时 enqueue 阻塞 ⇒ 反压到消费循环，
//     宁可慢、不可丢，并计入 persist_backpressure；
//   - 后台 persistLoop 攒批：满 flushBatchSize 条或距首条满 flushInterval（先到者）刷一次；
//   - 写入失败：记日志 + 该批留在本地重试（store.InsertAlerts 是单条原子 INSERT，
//     失败即一行未插入，故重试不会重复），每次失败累计 persist_errors；
//   - 成功：把 DB 返回的 id 回填到 Alert，再进环形缓冲 + 派发，persisted 累加。
//
// ★ 为什么以 DB 的 BIGSERIAL 为唯一 ID：内存与库必须共用同一个 id，否则前端
//
//      since_id 增量拉取会错乱。故先落库、拿到 id、回填、再进环形缓冲。

// startPersist 启动后台批量落库 goroutine（仅 alertStore != nil 时调用）。
func (s *Service) startPersist() {
	s.persistCh = make(chan Alert, persistQueueSize)
	s.persistQuit = make(chan struct{})
	s.persistWG.Add(1)
	go s.persistLoop()
}

// stopPersist 通知批量落库 goroutine 排空剩余队列并退出（幂等）。
func (s *Service) stopPersist() {
	if s.persistQuit == nil {
		return
	}
	s.persistStopOnce.Do(func() { close(s.persistQuit) })
	s.persistWG.Wait()
}

// enqueue 把一条告警投递到待写队列。
//
// ★ 队列满时阻塞（反压到事件消费循环），并累计 backpressure 便于观测。
func (s *Service) enqueue(a Alert) {
	select {
	case s.persistCh <- a:
		return
	default:
	}
	s.mu.Lock()
	s.backpressure++
	s.mu.Unlock()
	s.persistCh <- a
}

// persistLoop 后台攒批 + 批量落库。
func (s *Service) persistLoop() {
	defer s.persistWG.Done()

	batch := make([]Alert, 0, flushBatchSize)
	timer := time.NewTimer(flushInterval)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	for {
		// 阻塞等待首条（或退出信号）。
		select {
		case a := <-s.persistCh:
			batch = append(batch, a)
		case <-s.persistQuit:
			s.drainAndFlush(batch)
			return
		}

		// 满批立即刷，否则最多等 flushInterval 攒更多。
		if len(batch) >= flushBatchSize {
			s.flushBatch(&batch, 0)
			continue
		}

		timer.Reset(flushInterval)
	gather:
		for len(batch) < flushBatchSize {
			select {
			case a := <-s.persistCh:
				batch = append(batch, a)
			case <-timer.C:
				break gather
			case <-s.persistQuit:
				stopTimer(timer)
				s.drainAndFlush(batch)
				return
			}
		}
		stopTimer(timer)
		s.flushBatch(&batch, 0)
	}
}

// drainAndFlush 在退出前排空待写队列并尽量落库（限次重试，避免关停时永久卡住）。
func (s *Service) drainAndFlush(batch []Alert) {
	// 在关停路径上给重试设上限：DB 已彻底不可用时宁可放弃也不永久卡死。
	const shutdownRetries = 5
	for {
		select {
		case a := <-s.persistCh:
			batch = append(batch, a)
			if len(batch) >= flushBatchSize {
				s.flushBatch(&batch, shutdownRetries)
			}
		default:
			if len(batch) > 0 {
				s.flushBatch(&batch, shutdownRetries)
			}
			return
		}
	}
}

// flushBatch 把一批告警写入库；失败则重试（maxAttempts<=0 表示不限次数）。
//
// ★ 成功时：回填 DB id → 进环形缓冲 → 派发，保证内存与库的 id 完全一致。
// ★ 失败时：整批原样保留重试（InsertAlerts 为原子写入，不会重复插入）。
func (s *Service) flushBatch(batch *[]Alert, maxAttempts int) {
	items := *batch
	if len(items) == 0 {
		return
	}

	attempts := 0
	for {
		ids, err := s.alertStore.InsertAlerts(context.Background(), items)
		if err == nil {
			s.recordPersisted(items, ids)
			*batch = items[:0]
			return
		}

		s.mu.Lock()
		s.persistErrors++
		s.mu.Unlock()
		if s.logger != nil {
			s.logger.Warn("alerting: 批量入库失败，重试中", "count", len(items), "err", err)
		}
		attempts++
		if maxAttempts > 0 && attempts >= maxAttempts {
			if s.logger != nil {
				s.logger.Error("alerting: 批量入库连续失败，放弃该批（关停中）",
					"count", len(items), "err", err)
			}
			*batch = items[:0]
			return
		}
		time.Sleep(persistRetryDelay)
	}
}

// recordPersisted 回填 DB id 并把该批告警放进环形缓冲 + 派发。
func (s *Service) recordPersisted(items []Alert, ids []uint64) {
	if len(ids) != len(items) {
		// 理论上不会发生（单条 INSERT ... RETURNING 一一对应）；防御性记录。
		if s.logger != nil {
			s.logger.Error("alerting: 入库返回的 id 数量与告警数量不一致",
				"alerts", len(items), "ids", len(ids))
		}
	}
	for i := range items {
		if i < len(ids) {
			items[i].ID = ids[i]
		}
		rec := s.ring.addWithID(items[i])
		s.push(rec)
	}
	s.mu.Lock()
	s.persisted += uint64(len(items))
	s.mu.Unlock()
}

// stopTimer 安全停止并清空一次 timer（避免残留 tick 影响下一轮）。
func stopTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}
