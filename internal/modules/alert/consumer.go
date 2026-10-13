package alert

import (
	"sync"
	"sync/atomic"
	"time"

	"flow-monitoring/internal/kernel/eventbus"
)

const (
	// defaultDedupWindow 是去重窗口的默认值。
	defaultDedupWindow = 10 * time.Second
	// defaultSubBuffer 是 NewConsumerFromBus 的默认订阅缓冲。
	defaultSubBuffer = 4096
)

// ConsumerOptions 是消费者配置。
type ConsumerOptions struct {
	// DedupWindow 去重窗口；<=0 用默认 10s。
	DedupWindow time.Duration
	// Now 时间源（测试注入）；nil 用 time.Now。
	Now func() time.Time
}

// dedupKey 是去重键：规则 + 流。
type dedupKey struct {
	ruleID   string
	streamID int
}

// Consumer 从一个事件 channel 消费告警，去重后写入 Sink。
//
// ★ 只依赖 <-chan eventbus.Event，不绑定具体总线：将来消费者搬进独立插件
// 进程（事件经桥塞进 channel）时，本文件一行都不用改。
type Consumer struct {
	sink   Sink
	now    func() time.Time
	window time.Duration

	written    atomic.Uint64
	suppressed atomic.Uint64

	// mu 保护 last。
	mu   sync.Mutex
	last map[dedupKey]time.Time

	// done 关闭后消费循环退出。
	done chan struct{}
	// wg 等消费循环退出，保证 Close 返回后不再消费。
	wg sync.WaitGroup

	// 订阅由 NewConsumerFromBus 创建时才有；Close 负责退订。
	bus *eventbus.Bus
	sub *eventbus.Subscription

	closeOnce sync.Once
	closeErr  error
}

// NewConsumer 从一个事件 channel 消费告警。不订阅、不拥有该 channel。
func NewConsumer(ch <-chan eventbus.Event, sink Sink, opts ConsumerOptions) *Consumer {
	return newConsumer(ch, sink, opts, nil, nil)
}

// NewConsumerFromBus 便捷构造：订阅 topic（bufSize<=0 -> 4096）后用它的 channel 建消费者，
// 并让 Close 负责退订。
func NewConsumerFromBus(bus *eventbus.Bus, topic string, bufSize int, sink Sink, opts ConsumerOptions) *Consumer {
	if bufSize <= 0 {
		bufSize = defaultSubBuffer
	}
	sub := bus.Subscribe(topic, bufSize)
	return newConsumer(sub.C(), sink, opts, bus, sub)
}

// newConsumer 是内部构造：bus/sub 可为 nil（不订阅）。先把字段备齐再起循环，
// 避免 Close 与构造并发时漏退订。
func newConsumer(ch <-chan eventbus.Event, sink Sink, opts ConsumerOptions, bus *eventbus.Bus, sub *eventbus.Subscription) *Consumer {
	if opts.DedupWindow <= 0 {
		opts.DedupWindow = defaultDedupWindow
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	c := &Consumer{
		sink:   sink,
		now:    opts.Now,
		window: opts.DedupWindow,
		last:   make(map[dedupKey]time.Time),
		done:   make(chan struct{}),
		bus:    bus,
		sub:    sub,
	}
	c.wg.Add(1)
	go c.loop(ch)
	return c
}

// loop 是消费循环：done 关闭或 channel 关闭都退出。
func (c *Consumer) loop(ch <-chan eventbus.Event) {
	defer c.wg.Done()
	for {
		select {
		case <-c.done:
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			c.consume(ev)
		}
	}
}

// consume 处理一条事件。
//
// ★ P0 去重规则（文档 §4/§7）：
//   - 键 = (Alert.RuleID, Alert.StreamID)；
//   - 该键在 DedupWindow 内已写过 -> 丢弃（Suppressed++），不写 sink；
//   - 否则写 sink（成功则 Written++）并记住时间；
//   - 时间一律取 opts.Now()。
//
// P0 不写 hits 汇总行：被压制数只记内存计数。文档 §7 说的"累加 hits"
// 留 P1 用"窗口结束时补一条汇总记录"实现。
//
// Payload 不是 alert.Event（含 nil）时忽略，不 panic。
func (c *Consumer) consume(ev eventbus.Event) {
	a, ok := ev.Payload.(Event)
	if !ok {
		return
	}
	key := dedupKey{ruleID: a.Alert.RuleID, streamID: a.Alert.StreamID}

	now := c.now()
	c.mu.Lock()
	if last, seen := c.last[key]; seen && now.Sub(last) < c.window {
		c.mu.Unlock()
		c.suppressed.Add(1)
		return
	}
	c.last[key] = now
	c.mu.Unlock()

	if c.sink == nil {
		c.written.Add(1)
		return
	}
	if err := c.sink.Write(a); err != nil {
		return
	}
	c.written.Add(1)
}

// Written 返回已写入 sink 的告警数。
func (c *Consumer) Written() uint64 { return c.written.Load() }

// Suppressed 返回被去重压制的告警数（仅内存计数，P0 不落盘）。
func (c *Consumer) Suppressed() uint64 { return c.suppressed.Load() }

// Close 停止消费（关 done + 等循环退出）+ 若订阅由它创建则退订 + sink.Close()。
//
// 幂等：重复调用返回同一结果。
func (c *Consumer) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.wg.Wait() // 保证返回后消费循环已退出（确定性）
		if c.sub != nil && c.bus != nil {
			c.bus.Unsubscribe(c.sub)
		}
		if c.sink != nil {
			c.closeErr = c.sink.Close()
		}
	})
	return c.closeErr
}
