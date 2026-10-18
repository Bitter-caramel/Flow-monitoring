package alerting

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"flow-monitoring/internal/kernel/eventbus"
)

// Config 是 alerting 服务的装配配置。
type Config struct {
	// Capacity 是环形缓冲容量（沿用 config.Detect.AlertBuffer；<=0 用默认值）。
	Capacity int
	// Logger 可选：nil 时退回 slog.Default()（解析失败的日志不能静默丢）。
	Logger *slog.Logger
}

// Stats 是 /api/alerts/stats 的响应体。
//
// ★ 15-2b 起宿主不再加载规则、也不再跑回放：rules_total / rules_by_source /
// replay 这些它不知道的信息被移除，留着就是撒谎。
type Stats struct {
	Enabled      bool   `json:"enabled"`
	AlertsTotal  int    `json:"alerts_total"`
	Capacity     int    `json:"capacity"`
	Received     uint64 `json:"received"`
	Dropped      uint64 `json:"dropped"`
	DecodeErrors uint64 `json:"decode_errors"`
	LastError    string `json:"last_error"`
}

// Service 只订阅 detect.feature 事件并缓存告警，不加载规则、不跑热路径。
type Service struct {
	ring   *ring
	logger *slog.Logger

	mu        sync.Mutex
	enabled   bool
	sub       *eventbus.Subscription
	bus       *eventbus.Bus
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	received  uint64
	decodeErr uint64
	lastError string
}

// New 创建 alerting 服务（只装配环形缓冲与日志器，不启动订阅）。
func New(cfg Config) *Service {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		ring:   newRing(cfg.Capacity),
		logger: logger,
	}
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
	// ★ 在持锁时 Add，保证 Stop 的 Wait 不会与 Add 竞态。
	s.wg.Add(1)
	s.mu.Unlock()

	go s.consume(ctx, sub)
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

// Query 按 id 升序返回一页告警（参数语义见 ring.query）。
func (s *Service) Query(page, pageSize int, sinceID uint64) Page {
	if s == nil {
		return Page{Items: []Alert{}, Page: 1, PageSize: DefaultPageSize}
	}
	return s.ring.query(page, pageSize, sinceID)
}

// Stats 返回当前状态快照（并发安全）。
func (s *Service) Stats() Stats {
	if s == nil {
		return Stats{}
	}

	s.mu.Lock()
	enabled := s.enabled
	received := s.received
	decodeErr := s.decodeErr
	lastError := s.lastError
	s.mu.Unlock()

	return Stats{
		Enabled:      enabled,
		AlertsTotal:  s.ring.len(),
		Capacity:     s.ring.capacity(),
		Received:     received,
		Dropped:      s.ring.droppedCount(),
		DecodeErrors: decodeErr,
		LastError:    lastError,
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
	s.ring.add(a)
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
