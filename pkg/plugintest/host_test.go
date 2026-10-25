package plugintest

import (
	"testing"
	"time"

	"flow-monitoring/pkg/plugin"
)

// TestPublishIsRecorded 验证 Publish 只记录载荷副本，并可被 PublishedTo 取出。
func TestPublishIsRecorded(t *testing.T) {
	h := New()
	if err := h.Publish("detect.feature", []byte(`{"a":1}`)); err != nil {
		t.Fatalf("Publish 返回错误: %v", err)
	}
	if err := h.Publish("module.status", []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("Publish 返回错误: %v", err)
	}

	got := h.PublishedTo("detect.feature")
	if len(got) != 1 || string(got[0]) != `{"a":1}` {
		t.Fatalf("PublishedTo(detect.feature) = %v", got)
	}
	if n := len(h.PublishedTo("module.status")); n != 1 {
		t.Fatalf("PublishedTo(module.status) 条数 = %d, want 1", n)
	}
	if n := len(h.PublishedTo("nope")); n != 0 {
		t.Fatalf("PublishedTo(nope) 条数 = %d, want 0", n)
	}

	// 返回的是副本：修改不应影响内部记录。
	got[0][0] = 'X'
	if again := h.PublishedTo("detect.feature"); string(again[0]) != `{"a":1}` {
		t.Fatalf("PublishedTo 未返回副本: %q", again[0])
	}
}

// TestPollFuncIsCalled 验证脚本化的 PollFunc 会被调用，且参数被记录。
func TestPollFuncIsCalled(t *testing.T) {
	h := New()
	var calls int
	h.PollFunc = func(topic string, since uint64, max int) []plugin.EventRecord {
		calls++
		return []plugin.EventRecord{{Topic: topic, Seq: since + 1}}
	}

	got := h.Poll("detect.feature", 7, 3)
	if calls != 1 {
		t.Fatalf("PollFunc 调用次数 = %d, want 1", calls)
	}
	if len(got) != 1 || got[0].Seq != 8 {
		t.Fatalf("Poll 返回值 = %+v", got)
	}
	pc := h.PollCalls()
	if len(pc) != 1 || pc[0].Topic != "detect.feature" || pc[0].Since != 7 || pc[0].Max != 3 {
		t.Fatalf("PollCalls = %+v", pc)
	}
}

// TestHostNotRunStoreRunHostIs 守住两个类型的关键差异：
// Host 不实现 RunStore（用于测"宿主不支持持久化"），RunHost 实现。
func TestHostNotRunStoreRunHostIs(t *testing.T) {
	if _, ok := any(New()).(plugin.RunStore); ok {
		t.Fatal("Host 不应实现 plugin.RunStore")
	}
	var rs plugin.RunStore = NewRunHost()
	if err := rs.RunSave(plugin.RunRecord{ID: "r1", State: "done"}); err != nil {
		t.Fatalf("RunSave: %v", err)
	}
	if got := rs.RunList(10); len(got) != 0 {
		t.Fatalf("RunList 应只返回预置历史，got=%+v", got)
	}
	rh := NewRunHost(plugin.RunRecord{ID: "old"})
	if got := rh.RunList(10); len(got) != 1 || got[0].ID != "old" {
		t.Fatalf("RunList 预置历史 = %+v", got)
	}
	if got := rh.Saved(); len(got) != 0 {
		t.Fatalf("Saved = %+v", got)
	}
}

// TestLogAndMemoryStorage 验证日志与内存存储的默认行为。
func TestLogAndMemoryStorage(t *testing.T) {
	h := New()
	h.Log("info", "hello")
	h.Log("error", "boom")
	if got := h.LogsWithLevel("error"); len(got) != 1 || got[0].Msg != "boom" {
		t.Fatalf("LogsWithLevel(error) = %+v", got)
	}
	if !h.WaitLog("hello", time.Second) {
		t.Fatal("WaitLog 未等到 hello")
	}

	rec := plugin.CaptureRecord{ID: "cap-1", Name: "x"}
	if err := h.CaptureCreate(rec); err != nil {
		t.Fatalf("CaptureCreate: %v", err)
	}
	if got, ok := h.CaptureGet("cap-1"); !ok || got.Name != "x" {
		t.Fatalf("CaptureGet = %+v, %v", got, ok)
	}
	if _, ok := h.CaptureGet("missing"); ok {
		t.Fatal("CaptureGet(missing) 应返回 false")
	}
	if err := h.PacketSaveBatch("cap-1", []plugin.PacketRecord{{No: 1}, {No: 2}}); err != nil {
		t.Fatalf("PacketSaveBatch: %v", err)
	}
	if n := h.PacketCount("cap-1"); n != 2 {
		t.Fatalf("PacketCount = %d, want 2", n)
	}
}
