package pollsource

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/eventbus"
	"flow-monitoring/pkg/plugin"
)

// fakeHost 是只实现 Poll/Log 的可控宿主桩（其余方法满足接口即可）。
type fakeHost struct {
	mu      sync.Mutex
	records map[string][]plugin.EventRecord
	logs    []string
	calls   []pollCall

	// panicPoll 为 true 时 Poll 直接 panic，用于验证 Errors 计数。
	panicPoll bool
}

type pollCall struct {
	topic string
	since uint64
	max   int
}

var _ plugin.Host = (*fakeHost)(nil)

func newFakeHost() *fakeHost {
	return &fakeHost{records: make(map[string][]plugin.EventRecord)}
}

// append 追加一条记录并自动分配 Seq（模拟宿主 EventLog）。
func (h *fakeHost) append(topic string, seq uint64, data string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records[topic] = append(h.records[topic], plugin.EventRecord{
		Topic: topic,
		Seq:   seq,
		Data:  []byte(data),
		Time:  time.Unix(int64(seq), 0),
	})
}

func (h *fakeHost) Config() plugin.ConfigSnapshot { return plugin.ConfigSnapshot{} }

func (h *fakeHost) Log(level, msg string) {
	h.mu.Lock()
	h.logs = append(h.logs, level+"|"+msg)
	h.mu.Unlock()
}

func (h *fakeHost) Publish(string, []byte) error { return nil }

func (h *fakeHost) Poll(topic string, since uint64, max int) []plugin.EventRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, pollCall{topic: topic, since: since, max: max})
	if h.panicPoll {
		panic("fake poll panic")
	}
	if max <= 0 {
		max = 100
	}
	var out []plugin.EventRecord
	for _, ev := range h.records[topic] {
		if ev.Seq > since {
			out = append(out, ev)
			if len(out) >= max {
				break
			}
		}
	}
	return out
}

func (h *fakeHost) RegisterHTTP(string, string, string) error { return nil }
func (h *fakeHost) RegisterService(plugin.ServiceRef) error   { return nil }
func (h *fakeHost) LookupService(string) (plugin.ServiceRef, bool) {
	return plugin.ServiceRef{}, false
}
func (h *fakeHost) UnregisterService(string) error           { return nil }
func (h *fakeHost) CaptureCreate(plugin.CaptureRecord) error { return nil }
func (h *fakeHost) CaptureGet(string) (plugin.CaptureRecord, bool) {
	return plugin.CaptureRecord{}, false
}
func (h *fakeHost) CaptureList(plugin.Page) plugin.CapturePage          { return plugin.CapturePage{} }
func (h *fakeHost) CaptureDelete(string) error                          { return nil }
func (h *fakeHost) PacketSaveBatch(string, []plugin.PacketRecord) error { return nil }
func (h *fakeHost) PacketList(string, plugin.Page) plugin.PacketPage {
	return plugin.PacketPage{}
}
func (h *fakeHost) PacketCount(string) int    { return 0 }
func (h *fakeHost) PacketDelete(string) error { return nil }

func (h *fakeHost) logText() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.logs, "\n")
}

func (h *fakeHost) callsSnapshot() []pollCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]pollCall(nil), h.calls...)
}

// waitFor 轮询等待 cond 成立，超时即失败。
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

// recvN 从 channel 收 n 条事件（带超时），返回 Payload 字符串。
func recvN(t *testing.T, ch <-chan eventbus.Event, n int) []string {
	t.Helper()
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		select {
		case ev := <-ch:
			out = append(out, string(ev.Payload.([]byte)))
		case <-time.After(3 * time.Second):
			t.Fatalf("接收第 %d 条事件超时（已收 %v）", i+1, out)
		}
	}
	return out
}

// TestSourceDeliversInOrder 守住：连续三批事件按 Seq 递增投递，Since 正确推进。
func TestSourceDeliversInOrder(t *testing.T) {
	host := newFakeHost()
	const topic = "detect.feature"
	for i := uint64(1); i <= 3; i++ {
		host.append(topic, i, fmt.Sprintf("%d", i))
	}

	src := New(host, topic, Options{Batch: 2, Idle: 5 * time.Millisecond})
	defer src.Close()

	got := recvN(t, src.C(), 3)
	want := []string{"1", "2", "3"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("投递顺序 = %v, want %v", got, want)
		}
	}

	waitFor(t, "Delivered==3", func() bool { return src.Stats().Delivered == 3 })
	if st := src.Stats(); st.LastSeq != 3 {
		t.Errorf("LastSeq = %d, want 3", st.LastSeq)
	}

	// 至少有一次轮询的 since 已经推进到 2（第一批投完），再推进到 3。
	waitFor(t, "Since 推进到 3", func() bool {
		for _, c := range host.callsSnapshot() {
			if c.since == 3 {
				return true
			}
		}
		return false
	})
}

// TestSourceDetectsGapAndContinues 守住：Seq 跳号 ⇒ Gaps==1，且仍继续消费后续事件。
func TestSourceDetectsGapAndContinues(t *testing.T) {
	host := newFakeHost()
	const topic = "detect.feature"
	host.append(topic, 1, "1")

	src := New(host, topic, Options{Idle: 5 * time.Millisecond})
	defer src.Close()

	if got := recvN(t, src.C(), 1); got[0] != "1" {
		t.Fatalf("首条 = %q, want 1", got[0])
	}

	// 跳过 2..9，直接投 10（模拟宿主 ring 覆盖旧事件）。
	host.append(topic, 10, "10")
	host.append(topic, 11, "11")

	got := recvN(t, src.C(), 2)
	if got[0] != "10" || got[1] != "11" {
		t.Fatalf("断层后投递 = %v, want [10 11]", got)
	}

	waitFor(t, "Gaps==1", func() bool { return src.Stats().Gaps == 1 })
	waitFor(t, "Delivered==3", func() bool { return src.Stats().Delivered == 3 })
	if st := src.Stats(); st.LastSeq != 11 {
		t.Errorf("LastSeq = %d, want 11", st.LastSeq)
	}

	waitFor(t, "warn 日志含断层", func() bool {
		return strings.Contains(host.logText(), "断层")
	})
}

// TestSourceDetectsGapWithinBatch 守住：同一批里出现跳号也要计数（不能只看首条）。
func TestSourceDetectsGapWithinBatch(t *testing.T) {
	host := newFakeHost()
	const topic = "detect.feature"
	// 一次性放好 1 和 10：首条 1 不跳号，但批内 1→10 跳号。
	host.append(topic, 1, "1")
	host.append(topic, 10, "10")

	src := New(host, topic, Options{Batch: 10, Idle: 5 * time.Millisecond})
	defer src.Close()

	recvN(t, src.C(), 2)
	waitFor(t, "Gaps==1（批内跳号）", func() bool { return src.Stats().Gaps == 1 })
}

// TestSourceFromLatestSkipsHistory 守住：FromLatest=true 只投递构造之后的新事件。
func TestSourceFromLatestSkipsHistory(t *testing.T) {
	host := newFakeHost()
	const topic = "detect.feature"
	host.append(topic, 1, "old-1")
	host.append(topic, 2, "old-2")
	host.append(topic, 3, "old-3")

	src := New(host, topic, Options{FromLatest: true, Idle: 5 * time.Millisecond})
	defer src.Close()

	host.append(topic, 4, "new-4")

	got := recvN(t, src.C(), 1)
	if got[0] != "new-4" {
		t.Fatalf("FromLatest 投递 = %v, want [new-4]（必须跳过历史）", got)
	}
	// 再确认没有把历史事件混进来。
	select {
	case ev := <-src.C():
		t.Fatalf("FromLatest 不应再投递历史事件，实际收到 %q", string(ev.Payload.([]byte)))
	case <-time.After(30 * time.Millisecond):
	}

	waitFor(t, "Delivered==1 且 LastSeq==4", func() bool {
		st := src.Stats()
		return st.Delivered == 1 && st.LastSeq == 4
	})
}

// TestSourceCloseClosesChannel 守住：Close 后循环退出、channel 关闭（超时保护）。
func TestSourceCloseClosesChannel(t *testing.T) {
	host := newFakeHost()
	const topic = "no.events"
	src := New(host, topic, Options{Idle: time.Hour})

	done := make(chan struct{})
	go func() {
		for range src.C() {
		}
		close(done)
	}()

	src.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close 后 channel 未被关闭")
	}

	// 幂等。
	src.Close()
}

// TestSourceCountsPollPanic 守住：Poll 意外 panic 不打死循环，计 Errors 并继续。
func TestSourceCountsPollPanic(t *testing.T) {
	host := newFakeHost()
	host.panicPoll = true
	src := New(host, "x", Options{Idle: 5 * time.Millisecond})
	defer src.Close()

	waitFor(t, "Errors>0", func() bool { return src.Stats().Errors > 0 })
}
