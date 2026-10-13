package eventbus

import (
	"sync"
	"sync/atomic"
	"time"
)

// Event 事件总线上的消息。
//
// TraceID 对应实施方案 2.0 第 5.3 节"事件统一携带 trace_id"，
// 保证从告警到证据可回溯；由发布方填充（无则留空）。
type Event struct {
	Topic   string    `json:"topic"`
	Payload any       `json:"payload"`
	TraceID string    `json:"trace_id,omitempty"`
	Time    time.Time `json:"time"`
}

// Subscription 订阅句柄。
//
// 通过 C 读取事件；不再需要时调用 Unsubscribe。
// 注意：C 在 Bus.Close 或 Unsubscribe 时会被关闭；
// 关闭后 C 返回零值（ok=false）。
type Subscription struct {
	topic string
	id    uint64
	ch    chan Event
	bus   *Bus
}

// C 事件接收 channel（只读视图）。
func (s *Subscription) C() <-chan Event { return s.ch }

// Topic 订阅的主题。
func (s *Subscription) Topic() string { return s.topic }

// Bus 进程内事件总线。
//
// 线程安全；Publish 与 Subscribe/Unsubscribe 可并发。
type Bus struct {
	mu     sync.RWMutex
	subs   map[string]map[uint64]chan Event
	nextID uint64
	closed bool

	// dropped 累计丢弃的事件数（订阅者缓冲满时丢弃）。
	// 对应 v0.3 第 9.7 节"满则丢弃最低优先级特征并记 dropped 计数（可观测）"。
	dropped atomic.Uint64
}

// New 创建事件总线。
func New() *Bus {
	return &Bus{
		subs: make(map[string]map[uint64]chan Event),
	}
}

// Subscribe 订阅某主题，返回 Subscription。
//
// bufSize 为订阅者缓冲大小：
//   - bufSize <= 0 时默认 1024
//   - 缓冲满时事件被丢弃（Bus.dropped 计数自增），订阅者不会阻塞
//
// 使用模式：
//
//	sub := bus.Subscribe("traffic.flow", 4096)
//	defer bus.Unsubscribe(sub)
//	for ev := range sub.C() {
//	    // 处理 ev
//	}
func (b *Bus) Subscribe(topic string, bufSize int) *Subscription {
	if bufSize <= 0 {
		bufSize = 1024
	}
	ch := make(chan Event, bufSize)

	b.mu.Lock()
	defer b.mu.Unlock()

	id := b.nextID
	b.nextID++
	if b.subs[topic] == nil {
		b.subs[topic] = make(map[uint64]chan Event)
	}
	b.subs[topic][id] = ch

	return &Subscription{topic: topic, id: id, ch: ch, bus: b}
}

// Unsubscribe 取消订阅并关闭对应 channel。
//
// 幂等：重复调用无副作用。调用后不再从 C 接收新事件。
func (b *Bus) Unsubscribe(sub *Subscription) {
	if sub == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if m, ok := b.subs[sub.topic]; ok {
		if ch, exists := m[sub.id]; exists {
			delete(m, sub.id)
			close(ch)
			if len(m) == 0 {
				delete(b.subs, sub.topic)
			}
		}
	}
}

// Publish 向某主题广播事件。
//
// 行为：
//   - 无订阅者时静默返回（不报错）
//   - 有订阅者时，事件被投递到每个订阅者缓冲
//   - 订阅者缓冲满 → 丢弃该事件，dropped 自增，不影响其他订阅者
//   - Close 后调用 Publish 返回 ErrClosed
//
// 主题为空返回 ErrInvalidTopic。
func (b *Bus) Publish(topic string, payload any) error {
	return b.PublishEvent(Event{
		Topic:   topic,
		Payload: payload,
		Time:    time.Now(),
	})
}

// PublishEvent 广播一个已构造的 Event（允许发布方填充 TraceID）。
func (b *Bus) PublishEvent(ev Event) error {
	if ev.Topic == "" {
		return ErrInvalidTopic
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return ErrClosed
	}

	// 投递在读锁内完成，以保证与 Unsubscribe/Close 的 close(ch) 互斥：
	// 读锁阻止二者（写锁）在投递期间删除并关闭 channel。
	// 非阻塞发送（带 default）不会阻塞，因此持读锁投递不会死锁，
	// 且读锁之间不互斥，仍允许多个发布者并发。
	if m, ok := b.subs[ev.Topic]; ok {
		for _, ch := range m {
			select {
			case ch <- ev:
			default:
				// 缓冲满则丢弃并计数
				b.dropped.Add(1)
			}
		}
	}
	return nil
}

// Close 关闭事件总线。
//
// 行为：
//   - 后续 Publish 返回 ErrClosed
//   - 所有订阅 channel 关闭（订阅者 for range 正常退出）
//   - 幂等：重复调用无副作用
func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for topic, m := range b.subs {
		for _, ch := range m {
			close(ch)
		}
		delete(b.subs, topic)
	}
}

// Dropped 返回累计丢弃的事件数。
func (b *Bus) Dropped() uint64 { return b.dropped.Load() }

// SubscriberCount 返回当前活跃订阅者总数（健康检查/观测用）。
func (b *Bus) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	n := 0
	for _, m := range b.subs {
		n += len(m)
	}
	return n
}

// TopicCount 返回当前活跃主题数（观测用）。
func (b *Bus) TopicCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}
