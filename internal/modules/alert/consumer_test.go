package alert

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/eventbus"
)

// fakeSink 是只收集的内存 Sink。
type fakeSink struct {
	mu     sync.Mutex
	events []Event
	closed bool
}

func (s *fakeSink) Write(ev Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	return nil
}

func (s *fakeSink) Flush() error { return nil }

func (s *fakeSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *fakeSink) snapshot() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...)
}

// fakeClock 是可控时间源，供去重窗口测试注入。
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// waitFor 轮询等待 cond 成立，超时即失败（不死等）。
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("等待 %s 超时", what)
}

// TestConsumerWritesAlerts 守住：真实总线上不同 (RuleID,StreamID) 的告警都被写出。
func TestConsumerWritesAlerts(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()
	sink := &fakeSink{}
	c := NewConsumerFromBus(bus, TopicAlertLifecycle, 0, sink, ConsumerOptions{})
	defer c.Close()

	events := []Event{evFor("r1", 1, "a"), evFor("r1", 2, "b"), evFor("r2", 1, "c")}
	for i, ev := range events {
		if err := bus.Publish(TopicAlertLifecycle, ev); err != nil {
			t.Fatalf("Publish 第 %d 条失败: %v", i, err)
		}
	}
	waitFor(t, "Written==3", func() bool { return c.Written() == 3 })

	if got := sink.snapshot(); len(got) != 3 {
		t.Fatalf("sink 期望 3 条, 实际 %d 条", len(got))
	}
	if c.Suppressed() != 0 {
		t.Fatalf("不应有压制, 实际 %d", c.Suppressed())
	}
}

// TestConsumerDedup 守住：同键在去重窗口内只写一条，窗口过后再次写出。
func TestConsumerDedup(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1700000000, 0)}
	ch := make(chan eventbus.Event, 16)
	sink := &fakeSink{}
	c := NewConsumer(ch, sink, ConsumerOptions{DedupWindow: time.Second, Now: clock.Now})
	defer c.Close()

	ev := evFor("r1", 7, "dup")
	for i := 0; i < 5; i++ {
		ch <- eventbus.Event{Payload: ev}
	}
	waitFor(t, "Suppressed==4", func() bool { return c.Suppressed() == 4 })
	if c.Written() != 1 {
		t.Fatalf("窗口内期望只写 1 条, 实际 %d", c.Written())
	}

	clock.Advance(2 * time.Second) // 推过 DedupWindow
	ch <- eventbus.Event{Payload: ev}
	waitFor(t, "Written==2", func() bool { return c.Written() == 2 })
	if c.Suppressed() != 4 {
		t.Fatalf("期望压制 4 条, 实际 %d", c.Suppressed())
	}
	if got := sink.snapshot(); len(got) != 2 {
		t.Fatalf("sink 期望 2 条, 实际 %d 条", len(got))
	}
}

// TestConsumerDifferentKeyNotDeduped 守住：规则不同或流不同的告警互不去重。
func TestConsumerDifferentKeyNotDeduped(t *testing.T) {
	fixed := func() time.Time { return time.Unix(1700000000, 0) }
	ch := make(chan eventbus.Event, 16)
	sink := &fakeSink{}
	c := NewConsumer(ch, sink, ConsumerOptions{DedupWindow: time.Hour, Now: fixed})
	defer c.Close()

	ch <- eventbus.Event{Payload: evFor("r1", 1, "x")} // 基线键
	ch <- eventbus.Event{Payload: evFor("r1", 2, "y")} // 同规则、不同流
	ch <- eventbus.Event{Payload: evFor("r2", 1, "z")} // 同流、不同规则
	waitFor(t, "Written==3", func() bool { return c.Written() == 3 })

	if c.Suppressed() != 0 {
		t.Fatalf("不应有压制, 实际 %d", c.Suppressed())
	}
	if got := sink.snapshot(); len(got) != 3 {
		t.Fatalf("sink 期望 3 条, 实际 %d 条", len(got))
	}
}

// TestConsumerIgnoresWrongPayload 守住：Payload 不是 alert.Event（字符串/nil）时忽略且不 panic。
func TestConsumerIgnoresWrongPayload(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()
	sink := &fakeSink{}
	c := NewConsumerFromBus(bus, TopicAlertLifecycle, 0, sink, ConsumerOptions{})
	defer c.Close()

	if err := bus.Publish(TopicAlertLifecycle, "not-an-event"); err != nil {
		t.Fatalf("Publish 字符串失败: %v", err)
	}
	if err := bus.Publish(TopicAlertLifecycle, nil); err != nil {
		t.Fatalf("Publish nil 失败: %v", err)
	}
	// 再发一条正确的"哨兵"：它被处理即证明前面的错误负载已被消费且被忽略。
	if err := bus.Publish(TopicAlertLifecycle, evFor("r1", 1, "ok")); err != nil {
		t.Fatalf("Publish 哨兵失败: %v", err)
	}
	waitFor(t, "Written==1", func() bool { return c.Written() == 1 })

	if c.Written() != 1 {
		t.Fatalf("错误负载不应计数, 实际 Written=%d", c.Written())
	}
	if got := sink.snapshot(); len(got) != 1 {
		t.Fatalf("sink 期望 1 条, 实际 %d 条", len(got))
	}
}

// TestConsumerCloseStops 守住：Close 返回后消费循环已退出，再 Publish 不再增长。
func TestConsumerCloseStops(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()
	sink := &fakeSink{}
	c := NewConsumerFromBus(bus, TopicAlertLifecycle, 0, sink, ConsumerOptions{})

	if err := bus.Publish(TopicAlertLifecycle, evFor("r1", 1, "first")); err != nil {
		t.Fatalf("Publish 失败: %v", err)
	}
	waitFor(t, "Written==1", func() bool { return c.Written() == 1 })

	if err := c.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	if err := bus.Publish(TopicAlertLifecycle, evFor("r1", 2, "second")); err != nil {
		t.Fatalf("Close 后 Publish 失败: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if c.Written() != 1 {
		t.Fatalf("Close 后不应再写, 实际 Written=%d", c.Written())
	}
}

// TestConsumerCloseDrainsBuffered 守住：Close 必须等消费循环把订阅 channel
// 里已缓冲的事件排空后才返回，不能让 CLI 退出时丢掉已投递但未消费的告警。
func TestConsumerCloseDrainsBuffered(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()
	sink := &fakeSink{}
	c := NewConsumerFromBus(bus, TopicAlertLifecycle, 0, sink, ConsumerOptions{})

	// 连续投递 20 条不同键（RuleID/StreamID 均不同）的告警，保证不被去重压制。
	for i := 0; i < 20; i++ {
		if err := bus.Publish(TopicAlertLifecycle, evFor(fmt.Sprintf("r%d", i), i, "drain")); err != nil {
			t.Fatalf("Publish 第 %d 条失败: %v", i, err)
		}
	}

	// 立刻 Close（不等、不轮询）：Close 返回后计数必须是终值。
	if err := c.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	if got := c.Written(); got != 20 {
		t.Fatalf("Close 后 Written 期望 20, 实际 %d（缓冲事件被丢弃）", got)
	}
	if got := sink.snapshot(); len(got) != 20 {
		t.Fatalf("sink 期望 20 条, 实际 %d 条（缓冲事件被丢弃）", len(got))
	}
}

// TestConsumerCloseDrainsBufferedSmallBuffer 守住：订阅缓冲很小（4）时，
// Close 仍要把缓冲里剩余事件排空，20 条一条不丢。
func TestConsumerCloseDrainsBufferedSmallBuffer(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()
	sink := &fakeSink{}
	c := NewConsumerFromBus(bus, TopicAlertLifecycle, 4, sink, ConsumerOptions{})

	// 小缓冲下若一口气投递，总线会在缓冲满时丢弃（Publish 非阻塞），
	// 那就测不到 Close 了。故先逐条投递前 16 条并各等到被消费（缓冲因此
	// 始终有空位），再一口气投递最后 4 条（恰好填满 4 格缓冲）后立刻 Close，
	// 验证 Close 会把缓冲里剩余事件排空。
	for i := 0; i < 16; i++ {
		if err := bus.Publish(TopicAlertLifecycle, evFor(fmt.Sprintf("s%d", i), i, "small")); err != nil {
			t.Fatalf("Publish 第 %d 条失败: %v", i, err)
		}
		want := uint64(i + 1)
		waitFor(t, fmt.Sprintf("Written==%d", want), func() bool { return c.Written() == want })
	}
	for i := 16; i < 20; i++ {
		if err := bus.Publish(TopicAlertLifecycle, evFor(fmt.Sprintf("s%d", i), i, "small")); err != nil {
			t.Fatalf("Publish 第 %d 条失败: %v", i, err)
		}
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	if got := c.Written(); got != 20 {
		t.Fatalf("Close 后 Written 期望 20, 实际 %d（小缓冲事件被丢弃）", got)
	}
	if got := sink.snapshot(); len(got) != 20 {
		t.Fatalf("sink 期望 20 条, 实际 %d 条（小缓冲事件被丢弃）", len(got))
	}
}

// evFlow 基于 evFor 造一条告警，但覆盖 FlowKey（方向化五元组），
// 用于验证 StreamID 缺失（<0，当前=IPv6）时 FlowKey 兜底参与去重键。
func evFlow(ruleID string, streamID int, flowKey string) Event {
	ev := evFor(ruleID, streamID, "flow")
	ev.Alert.FlowKey = flowKey
	return ev
}

// TestConsumerIPv6DifferentFlowNotDeduped 守住：StreamID 缺失（-1，当前=IPv6）
// 时，同一条规则下不同流（FlowKey 不同）的告警不再互相压制。
// ★ 改前此用例为红：两条都被压成 (ruleID,-1) 的同键，只写 1 条。
func TestConsumerIPv6DifferentFlowNotDeduped(t *testing.T) {
	fixed := func() time.Time { return time.Unix(1700000000, 0) }
	ch := make(chan eventbus.Event, 16)
	sink := &fakeSink{}
	c := NewConsumer(ch, sink, ConsumerOptions{DedupWindow: time.Hour, Now: fixed})
	defer c.Close()

	ch <- eventbus.Event{Payload: evFlow("r1", -1, "2408:1::1:443->2408:1::2:39912/tcp")}
	ch <- eventbus.Event{Payload: evFlow("r1", -1, "2408:3::1:443->2408:3::2:50000/tcp")}
	waitFor(t, "Written==2", func() bool { return c.Written() == 2 })

	if c.Written() != 2 {
		t.Fatalf("不同 IPv6 流应各写一条, 实际 Written=%d", c.Written())
	}
	if c.Suppressed() != 0 {
		t.Fatalf("不同 IPv6 流不应互相压制, 实际 Suppressed=%d", c.Suppressed())
	}
	if got := sink.snapshot(); len(got) != 2 {
		t.Fatalf("sink 期望 2 条, 实际 %d 条", len(got))
	}
}

// TestConsumerIPv6SameFlowDeduped 守住：StreamID 缺失（-1）时，同一流
// （FlowKey 相同）窗口内的重复告警仍被压制。
func TestConsumerIPv6SameFlowDeduped(t *testing.T) {
	fixed := func() time.Time { return time.Unix(1700000000, 0) }
	ch := make(chan eventbus.Event, 16)
	sink := &fakeSink{}
	c := NewConsumer(ch, sink, ConsumerOptions{DedupWindow: time.Hour, Now: fixed})
	defer c.Close()

	flow := "2408:1::1:443->2408:1::2:39912/tcp"
	ch <- eventbus.Event{Payload: evFlow("r1", -1, flow)}
	ch <- eventbus.Event{Payload: evFlow("r1", -1, flow)}
	waitFor(t, "Suppressed==1", func() bool { return c.Suppressed() == 1 })

	if c.Written() != 1 {
		t.Fatalf("同一 IPv6 流窗口内应只写 1 条, 实际 Written=%d", c.Written())
	}
	if c.Suppressed() != 1 {
		t.Fatalf("期望压制 1 条, 实际 %d", c.Suppressed())
	}
	if got := sink.snapshot(); len(got) != 1 {
		t.Fatalf("sink 期望 1 条, 实际 %d 条", len(got))
	}
}

// TestConsumerIPv4IgnoresFlowKey 守住：StreamID>=0（IPv4 既有行为）时 FlowKey
// 不参与去重键 —— 即使 FlowKey 故意不同，同一 (ruleID, streamID) 仍只写 1 条。
func TestConsumerIPv4IgnoresFlowKey(t *testing.T) {
	fixed := func() time.Time { return time.Unix(1700000000, 0) }
	ch := make(chan eventbus.Event, 16)
	sink := &fakeSink{}
	c := NewConsumer(ch, sink, ConsumerOptions{DedupWindow: time.Hour, Now: fixed})
	defer c.Close()

	ch <- eventbus.Event{Payload: evFlow("r1", 7, "10.0.0.1:1->10.0.0.2:2/tcp")}
	ch <- eventbus.Event{Payload: evFlow("r1", 7, "10.0.0.9:9->10.0.0.8:8/udp")}
	waitFor(t, "Suppressed==1", func() bool { return c.Suppressed() == 1 })

	if c.Written() != 1 {
		t.Fatalf("IPv4(StreamID>=0) 去重不应受 FlowKey 影响, 期望写 1 条, 实际 %d", c.Written())
	}
	if c.Suppressed() != 1 {
		t.Fatalf("期望压制 1 条, 实际 %d", c.Suppressed())
	}
}

// TestConsumerIPv6EmptyFlowKeyFallsBack 守住：StreamID<0 且 FlowKey 为空时
// 退化为旧行为（同键压制），不 panic、不放宽去重。
func TestConsumerIPv6EmptyFlowKeyFallsBack(t *testing.T) {
	fixed := func() time.Time { return time.Unix(1700000000, 0) }
	ch := make(chan eventbus.Event, 16)
	sink := &fakeSink{}
	c := NewConsumer(ch, sink, ConsumerOptions{DedupWindow: time.Hour, Now: fixed})
	defer c.Close()

	ch <- eventbus.Event{Payload: evFlow("r1", -1, "")}
	ch <- eventbus.Event{Payload: evFlow("r1", -1, "")}
	waitFor(t, "Suppressed==1", func() bool { return c.Suppressed() == 1 })

	if c.Written() != 1 {
		t.Fatalf("FlowKey 为空应退化为旧行为只写 1 条, 实际 %d", c.Written())
	}
	if c.Suppressed() != 1 {
		t.Fatalf("期望压制 1 条, 实际 %d", c.Suppressed())
	}
}
