// Package modulestatus 订阅模块自报状态（module.status 主题）并在内存维护快照。
//
// 方向：模块 → 宿主。模块进程的 plugin.Runtime 在 Start 成功后定期
// Publish("module.status", <StatusReport JSON>)；本包订阅该主题，按 module_id
// 保存最近一条状态，供 modulecontrol 的模块视图展示。
//
// ★ 不改 plugin.Host 契约：复用已有的 Publish，宿主这边只做订阅与存储。
package modulestatus

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"flow-monitoring/internal/kernel/eventbus"
	"flow-monitoring/pkg/plugin"
)

// Status 是宿主侧保存的模块状态快照。
type Status struct {
	ModuleID string `json:"module_id"`
	Healthy  bool   `json:"healthy"`
	Message  string `json:"message"`
	// Metrics 是模块自报的运行指标（键值均为字符串，gob/JSON 安全）。
	Metrics map[string]string `json:"metrics"`
	// At 是模块自报的状态生成时间；缺失时用事件时间兜底。
	At time.Time `json:"at"`
	// ReceivedAt 是宿主收到该状态的时间。
	ReceivedAt time.Time `json:"received_at"`
}

// Store 是模块状态的内存快照表（并发安全）。
type Store struct {
	mu       sync.RWMutex
	statuses map[string]Status

	// 订阅与消费 goroutine 的启停控制。
	muStop sync.Mutex
	sub    *eventbus.Subscription
	bus    *eventbus.Bus
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New 创建空的状态表。
func New() *Store {
	return &Store{statuses: make(map[string]Status)}
}

// Start 订阅 topic（空则用 plugin.StatusTopic）并起后台 goroutine 消费。
//
// 幂等：已在运行时再调用是 no-op。
func (s *Store) Start(bus *eventbus.Bus, topic string) {
	if s == nil || bus == nil {
		return
	}
	if topic == "" {
		topic = plugin.StatusTopic
	}

	s.muStop.Lock()
	if s.sub != nil { // 已在运行
		s.muStop.Unlock()
		return
	}
	sub := bus.Subscribe(topic, 256)
	ctx, cancel := context.WithCancel(context.Background())
	s.sub = sub
	s.bus = bus
	s.cancel = cancel
	s.wg.Add(1)
	s.muStop.Unlock()

	go s.consume(ctx, sub)
}

// Stop 取消消费 goroutine 并退订（幂等）。
func (s *Store) Stop() {
	if s == nil {
		return
	}
	s.muStop.Lock()
	cancel := s.cancel
	sub := s.sub
	bus := s.bus
	s.cancel = nil
	s.sub = nil
	s.bus = nil
	s.muStop.Unlock()

	if cancel == nil { // 已停止
		return
	}
	cancel()
	s.wg.Wait()
	if bus != nil && sub != nil {
		bus.Unsubscribe(sub)
	}
}

// consume 循环读取订阅事件并落表。
func (s *Store) consume(ctx context.Context, sub *eventbus.Subscription) {
	defer s.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-sub.C():
			if !ok {
				return
			}
			s.apply(ev)
		}
	}
}

// apply 解析一条事件并更新对应模块的状态。
func (s *Store) apply(ev eventbus.Event) {
	raw, ok := payloadBytes(ev.Payload)
	if !ok {
		return
	}
	var rep plugin.StatusReport
	if err := json.Unmarshal(raw, &rep); err != nil || rep.ModuleID == "" {
		return
	}
	metrics := rep.Metrics
	if metrics == nil {
		metrics = map[string]string{}
	}
	at := rep.At
	if at.IsZero() {
		at = ev.Time
	}
	s.mu.Lock()
	s.statuses[rep.ModuleID] = Status{
		ModuleID:   rep.ModuleID,
		Healthy:    rep.Healthy,
		Message:    rep.Message,
		Metrics:    metrics,
		At:         at,
		ReceivedAt: time.Now(),
	}
	s.mu.Unlock()
}

// Get 返回指定模块的最新状态（metrics 为副本，调用方可安全持有）。
func (s *Store) Get(id string) (Status, bool) {
	if s == nil {
		return Status{}, false
	}
	s.mu.RLock()
	st, ok := s.statuses[id]
	s.mu.RUnlock()
	if !ok {
		return Status{}, false
	}
	return copyStatus(st), true
}

// All 返回全部模块状态的副本（按 module_id 索引）。
func (s *Store) All() map[string]Status {
	if s == nil {
		return map[string]Status{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]Status, len(s.statuses))
	for id, st := range s.statuses {
		out[id] = copyStatus(st)
	}
	return out
}

// copyStatus 深拷贝 metrics，避免调用方改动内部快照。
func copyStatus(st Status) Status {
	var m map[string]string
	if st.Metrics != nil {
		m = make(map[string]string, len(st.Metrics))
		for k, v := range st.Metrics {
			m[k] = v
		}
	}
	st.Metrics = m
	return st
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
