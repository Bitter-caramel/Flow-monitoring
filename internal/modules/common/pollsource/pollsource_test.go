package pollsource

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/eventbus"
	"flow-monitoring/pkg/plugin"
	"flow-monitoring/pkg/plugintest"
)

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
	host := plugintest.New()
	const topic = "detect.feature"
	for i := uint64(1); i <= 3; i++ {
		host.Append(topic, i, []byte(fmt.Sprintf("%d", i)))
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
		for _, c := range host.PollCalls() {
			if c.Since == 3 {
				return true
			}
		}
		return false
	})
}

// TestSourceDetectsGapAndContinues 守住：Seq 跳号 ⇒ Gaps==1，且仍继续消费后续事件。
func TestSourceDetectsGapAndContinues(t *testing.T) {
	host := plugintest.New()
	const topic = "detect.feature"
	host.Append(topic, 1, []byte("1"))

	src := New(host, topic, Options{Idle: 5 * time.Millisecond})
	defer src.Close()

	if got := recvN(t, src.C(), 1); got[0] != "1" {
		t.Fatalf("首条 = %q, want 1", got[0])
	}

	// 跳过 2..9，直接投 10（模拟宿主 ring 覆盖旧事件）。
	host.Append(topic, 10, []byte("10"))
	host.Append(topic, 11, []byte("11"))

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
		return strings.Contains(host.LogText(), "断层")
	})
}

// TestSourceDetectsGapWithinBatch 守住：同一批里出现跳号也要计数（不能只看首条）。
func TestSourceDetectsGapWithinBatch(t *testing.T) {
	host := plugintest.New()
	const topic = "detect.feature"
	// 一次性放好 1 和 10：首条 1 不跳号，但批内 1→10 跳号。
	host.Append(topic, 1, []byte("1"))
	host.Append(topic, 10, []byte("10"))

	src := New(host, topic, Options{Batch: 10, Idle: 5 * time.Millisecond})
	defer src.Close()

	recvN(t, src.C(), 2)
	waitFor(t, "Gaps==1（批内跳号）", func() bool { return src.Stats().Gaps == 1 })
}

// TestSourceFromLatestSkipsHistory 守住：FromLatest=true 只投递构造之后的新事件。
func TestSourceFromLatestSkipsHistory(t *testing.T) {
	host := plugintest.New()
	const topic = "detect.feature"
	host.Append(topic, 1, []byte("old-1"))
	host.Append(topic, 2, []byte("old-2"))
	host.Append(topic, 3, []byte("old-3"))

	src := New(host, topic, Options{FromLatest: true, Idle: 5 * time.Millisecond})
	defer src.Close()

	host.Append(topic, 4, []byte("new-4"))

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
	host := plugintest.New()
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
	host := plugintest.New()
	host.PollFunc = func(string, uint64, int) []plugin.EventRecord { panic("fake poll panic") }
	src := New(host, "x", Options{Idle: 5 * time.Millisecond})
	defer src.Close()

	waitFor(t, "Errors>0", func() bool { return src.Stats().Errors > 0 })
}
