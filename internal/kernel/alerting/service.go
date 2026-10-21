package alerting

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

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
	// onAlert 是分配 id 并写入环形缓冲后回调的钩子（可为 nil）。
	onAlert func(Alert)
	// pushCh 是有界派发通道；只由 consume goroutine 投递、dispatch goroutine 消费。
	pushCh chan Alert
	// pushDropped 是派发通道满时丢弃的条数（受 mu 保护）。
	pushDropped uint64
}

// New 创建 alerting 服务（只装配环形缓冲与日志器，不启动订阅）。
func New(cfg Config) *Service {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	pushBuf := cfg.PushBuffer
	if pushBuf <= 0 {
		pushBuf = DefaultPushBuffer
	}
	return &Service{
		ring:    newRing(cfg.Capacity),
		logger:  logger,
		pushBuf: pushBuf,
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

// Query 按 id 升序返回一页告警（可选按 mode/run_id 过滤，见 ring.query）。
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
	s.mu.Lock()
	s.received++
	s.mu.Unlock()

	raw, ok := payloadBytes(ev.Payload)
	if !ok {
		s.recordDecodeError(fmt.Errorf("alerting: 事件载荷类型 %T 不是字节（期望 []byte / json.RawMessage）", ev.Payload))
		return
	}

	var a Alert
	if err := json.Unmarshal(raw, &a); err != nil {
		s.recordDecodeError(fmt.Errorf("alerting: 解析 detect.feature 告警失败: %w", err))
		return
	}
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
	s.decodeErr++
	s.lastError = msg
	s.mu.Unlock()

	if s.logger != nil {
		s.logger.Warn("alerting: 丢弃无法解析的事件", "err", msg)
	}
}
