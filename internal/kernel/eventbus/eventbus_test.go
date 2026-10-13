package eventbus

import (
	"errors"
	"testing"
	"time"
)

// TestPublishSubscribe 基本发布订阅。
func TestPublishSubscribe(t *testing.T) {
	bus := New()
	sub := bus.Subscribe("test.topic", 16)
	defer bus.Unsubscribe(sub)

	if err := bus.Publish("test.topic", "hello"); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case ev := <-sub.C():
		if ev.Topic != "test.topic" {
			t.Errorf("Topic = %q, want test.topic", ev.Topic)
		}
		if ev.Payload != "hello" {
			t.Errorf("Payload = %v, want hello", ev.Payload)
		}
		if ev.Time.IsZero() {
			t.Error("Time should not be zero")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}

// TestPublish_MultipleSubscribers 一个主题多个订阅者都收到。
func TestPublish_MultipleSubscribers(t *testing.T) {
	bus := New()
	s1 := bus.Subscribe("t", 4)
	s2 := bus.Subscribe("t", 4)
	defer bus.Unsubscribe(s1)
	defer bus.Unsubscribe(s2)

	_ = bus.Publish("t", "x")
	_ = bus.Publish("t", "y")

	for _, sub := range []*Subscription{s1, s2} {
		for _, want := range []string{"x", "y"} {
			select {
			case ev := <-sub.C():
				if ev.Payload != want {
					t.Errorf("payload = %v, want %s", ev.Payload, want)
				}
			case <-time.After(time.Second):
				t.Fatal("timeout")
			}
		}
	}
}

// TestPublish_NoSubscriber 无订阅者静默返回。
func TestPublish_NoSubscriber(t *testing.T) {
	bus := New()
	if err := bus.Publish("nobody.here", "x"); err != nil {
		t.Errorf("Publish with no subscriber should not error, got %v", err)
	}
}

// TestPublish_InvalidTopic 空主题报错。
func TestPublish_InvalidTopic(t *testing.T) {
	bus := New()
	if err := bus.Publish("", "x"); !errors.Is(err, ErrInvalidTopic) {
		t.Errorf("want ErrInvalidTopic, got %v", err)
	}
}

// TestUnsubscribe 取消订阅后不再接收。
func TestUnsubscribe(t *testing.T) {
	bus := New()
	sub := bus.Subscribe("t", 4)
	bus.Unsubscribe(sub)
	// 订阅者数为 0
	if bus.SubscriberCount() != 0 {
		t.Errorf("SubscriberCount = %d, want 0", bus.SubscriberCount())
	}
	// C 已关闭
	if _, ok := <-sub.C(); ok {
		t.Error("channel should be closed after Unsubscribe")
	}
	// 幂等
	bus.Unsubscribe(sub)
	bus.Unsubscribe(nil) // nil 不 panic
}

// TestPublish_BackpressureDrop 缓冲满时丢弃并计数。
func TestPublish_BackpressureDrop(t *testing.T) {
	bus := New()
	sub := bus.Subscribe("t", 2)
	defer bus.Unsubscribe(sub)

	// 不消费，连续发布 5 条；缓冲 2 条，后续 3 条丢弃
	for i := 0; i < 5; i++ {
		_ = bus.Publish("t", i)
	}
	if got := bus.Dropped(); got != 3 {
		t.Errorf("Dropped = %d, want 3", got)
	}
	// 缓冲中应仍有 2 条可读
	if got := len(sub.ch); got != 2 {
		t.Errorf("buffered = %d, want 2", got)
	}
}

// TestClose 关闭后发布报错，订阅 channel 关闭。
func TestClose(t *testing.T) {
	bus := New()
	sub := bus.Subscribe("t", 4)
	bus.Close()

	if err := bus.Publish("t", "x"); !errors.Is(err, ErrClosed) {
		t.Errorf("want ErrClosed, got %v", err)
	}
	if _, ok := <-sub.C(); ok {
		t.Error("channel should be closed after Close")
	}
	// 幂等
	bus.Close()
}

// TestPublishEvent_TraceID 自定义 TraceID 透传。
func TestPublishEvent_TraceID(t *testing.T) {
	bus := New()
	sub := bus.Subscribe("t", 4)
	defer bus.Unsubscribe(sub)

	_ = bus.PublishEvent(Event{
		Topic:   "t",
		Payload: "x",
		TraceID: "trace-123",
		Time:    time.Now(),
	})

	ev := <-sub.C()
	if ev.TraceID != "trace-123" {
		t.Errorf("TraceID = %q, want trace-123", ev.TraceID)
	}
}

// TestSubscriberAndTopicCount 观测计数。
func TestSubscriberAndTopicCount(t *testing.T) {
	bus := New()
	s1 := bus.Subscribe("a", 1)
	s2 := bus.Subscribe("b", 1)
	s3 := bus.Subscribe("b", 1)
	defer bus.Unsubscribe(s1)
	defer bus.Unsubscribe(s2)
	defer bus.Unsubscribe(s3)

	if bus.TopicCount() != 2 {
		t.Errorf("TopicCount = %d, want 2", bus.TopicCount())
	}
	if bus.SubscriberCount() != 3 {
		t.Errorf("SubscriberCount = %d, want 3", bus.SubscriberCount())
	}
}

// TestDefaultBufSize 非正 bufSize 回退默认 1024。
func TestDefaultBufSize(t *testing.T) {
	bus := New()
	sub := bus.Subscribe("t", 0)
	defer bus.Unsubscribe(sub)
	if cap(sub.ch) != 1024 {
		t.Errorf("buf cap = %d, want 1024", cap(sub.ch))
	}
}

// TestPublishUnsubscribeRace 验证并发 Publish 与 Subscribe/Unsubscribe 不会 panic。
//
// 现有测试均为顺序调用，从未覆盖 PublishEvent 在解锁后投递、
// 而 Unsubscribe/Close 同时 close(ch) 的竞态路径。
func TestPublishUnsubscribeRace(t *testing.T) {
	bus := New()
	stop := make(chan struct{})

	const producers = 8
	exited := make(chan struct{}, producers)
	for p := 0; p < producers; p++ {
		go func(base int) {
			i := base
			for {
				select {
				case <-stop:
					exited <- struct{}{}
					return
				default:
				}
				_ = bus.Publish("race.topic", i)
				i++
			}
		}(p)
	}

	for round := 0; round < 50000; round++ {
		sub := bus.Subscribe("race.topic", 1)
		bus.Unsubscribe(sub)
	}

	close(stop)
	for p := 0; p < producers; p++ {
		<-exited
	}
	bus.Close()
}
