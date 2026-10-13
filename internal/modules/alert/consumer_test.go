package alert

import (
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
