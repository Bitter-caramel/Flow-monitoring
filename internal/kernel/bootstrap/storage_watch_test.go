package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/logging"
	"flow-monitoring/internal/kernel/storage"
)

// —— 测试替身 ——

// fakeStorage 是 storage.Storage 的最小替身；巡检测试不解引用各 Store。
type fakeStorage struct {
	mu     sync.Mutex
	closed bool
}

func (f *fakeStorage) Captures() storage.CaptureStore { return nil }
func (f *fakeStorage) Packets() storage.PacketStore   { return nil }

func (f *fakeStorage) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

// fakeProbe 是行为可控的 storageProbe 假实现（不连真库）。
type fakeProbe struct {
	mu         sync.Mutex
	openDB     storage.Storage
	openErr    error
	pingErr    error
	opens      int
	pings      int
	closes     int
	lastClosed storage.Storage
}

func (f *fakeProbe) setOpen(db storage.Storage, err error) {
	f.mu.Lock()
	f.openDB = db
	f.openErr = err
	f.mu.Unlock()
}

func (f *fakeProbe) setPing(err error) {
	f.mu.Lock()
	f.pingErr = err
	f.mu.Unlock()
}

func (f *fakeProbe) Open(ctx context.Context) (storage.Storage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opens++
	if f.openErr != nil {
		return nil, f.openErr
	}
	return f.openDB, nil
}

func (f *fakeProbe) Ping(ctx context.Context, db storage.Storage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pings++
	return f.pingErr
}

func (f *fakeProbe) Close(db storage.Storage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes++
	f.lastClosed = db
}

func (f *fakeProbe) counts() (opens, pings, closes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opens, f.pings, f.closes
}

func (f *fakeProbe) closedHandle() storage.Storage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastClosed
}

// applyLog 记录 storageWatch 调用的 apply 参数（含 nil，= 降级通知）。
type applyLog struct {
	mu  sync.Mutex
	got []storage.Storage
}

func (a *applyLog) apply(db storage.Storage) {
	a.mu.Lock()
	a.got = append(a.got, db)
	a.mu.Unlock()
}

func (a *applyLog) snapshot() []storage.Storage {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]storage.Storage, len(a.got))
	copy(out, a.got)
	return out
}

func (a *applyLog) nilCount() int {
	n := 0
	for _, db := range a.snapshot() {
		if db == nil {
			n++
		}
	}
	return n
}

// lineCounter 统计写入的日志行数（每条 slog record 一行）。
type lineCounter struct {
	mu    sync.Mutex
	lines int
}

func (c *lineCounter) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.lines += bytes.Count(p, []byte("\n"))
	c.mu.Unlock()
	return len(p), nil
}

func (c *lineCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lines
}

func quietLogger() *logging.Logger {
	return logging.New(logging.LevelDebug, "json", io.Discard)
}

// —— 测试 ——

// TestWatch_RecoversWhenOpenSucceeds：不可用 ⇒ Open 成功 ⇒ 自动恢复并 apply(db)。
func TestWatch_RecoversWhenOpenSucceeds(t *testing.T) {
	probe := &fakeProbe{openErr: errors.New("db down")}
	applied := &applyLog{}
	w := newStorageWatch(probe, applied.apply, quietLogger())

	// 第 1 次 tick：Open 失败，保持不可用。
	w.tick(context.Background())
	if st := w.Status(); st.Available || st.Err == "" {
		t.Fatalf("after failed open: want unavailable with err, got %+v", st)
	}

	// 第 2 次 tick：Open 成功 ⇒ 恢复。
	db := &fakeStorage{}
	probe.setOpen(db, nil)
	w.tick(context.Background())

	st := w.Status()
	if !st.Available {
		t.Fatalf("want available after successful open, got %+v", st)
	}
	if st.Err != "" {
		t.Fatalf("want cleared err after recovery, got %q", st.Err)
	}
	got := applied.snapshot()
	if len(got) != 1 || got[0] != db {
		t.Fatalf("want apply(%p) once, got %v", db, got)
	}
}

// TestWatch_GoesUnavailableOnPingFailure：可用 ⇒ Ping 失败 ⇒ 降级并 apply(nil)。
func TestWatch_GoesUnavailableOnPingFailure(t *testing.T) {
	db := &fakeStorage{}
	probe := &fakeProbe{openDB: db}
	applied := &applyLog{}
	w := newStorageWatch(probe, applied.apply, quietLogger())
	w.seed(db) // 初始即可用

	probe.setPing(errors.New("connection reset by peer"))
	w.tick(context.Background())

	st := w.Status()
	if st.Available {
		t.Fatalf("want unavailable after ping failure, got %+v", st)
	}
	if st.Err == "" {
		t.Fatal("want non-empty err after ping failure")
	}
	if applied.nilCount() != 1 {
		t.Fatalf("want apply(nil) once (downgrade), got %v", applied.snapshot())
	}
	_, _, closes := probe.counts()
	if closes != 1 {
		t.Fatalf("want bad handle closed once, got %d", closes)
	}
	if probe.closedHandle() != db {
		t.Fatalf("want closed handle %p, got %p", db, probe.closedHandle())
	}
}

// TestWatch_SinceChangesOnlyOnFlip：状态不变时 Since 不能变。
func TestWatch_SinceChangesOnlyOnFlip(t *testing.T) {
	db := &fakeStorage{}
	probe := &fakeProbe{openDB: db}
	w := newStorageWatch(probe, func(storage.Storage) {}, quietLogger())
	w.seed(db)

	first := w.Status().Since
	for i := 0; i < 5; i++ {
		w.tick(context.Background())
		if got := w.Status().Since; !got.Equal(first) {
			t.Fatalf("tick %d moved Since without a state flip: %v -> %v", i, first, got)
		}
	}
}

// TestWatch_NoLogSpamWhileFailing：连续同样的 Open 失败只打 1 条日志。
func TestWatch_NoLogSpamWhileFailing(t *testing.T) {
	probe := &fakeProbe{openErr: errors.New("db down")}
	counter := &lineCounter{}
	w := newStorageWatch(probe, func(storage.Storage) {},
		logging.New(logging.LevelDebug, "json", counter))

	for i := 0; i < 3; i++ {
		w.tick(context.Background())
	}
	if got := counter.count(); got != 1 {
		t.Fatalf("want exactly 1 log line for 3 identical failures, got %d", got)
	}
	if opens, _, _ := probe.counts(); opens != 3 {
		t.Fatalf("want 3 open attempts, got %d", opens)
	}
}

// TestWatch_StopIdempotent：Stop 两次不 panic，停止后不再 tick。
func TestWatch_StopIdempotent(t *testing.T) {
	db := &fakeStorage{}
	probe := &fakeProbe{openDB: db}
	w := newStorageWatch(probe, func(storage.Storage) {}, quietLogger())
	w.interval = 20 * time.Millisecond // 测试注入更短周期
	w.seed(db)
	w.Start(context.Background())

	// 等第一次 tick（Ping 分支）。
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, pings, _ := probe.counts(); pings > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("watch did not tick after Start")
		}
		time.Sleep(5 * time.Millisecond)
	}

	w.Stop()
	w.Stop() // 幂等：不得 panic

	_, pingsAfterStop, _ := probe.counts()
	time.Sleep(120 * time.Millisecond) // 远超 interval
	_, pingsLater, _ := probe.counts()
	if pingsLater != pingsAfterStop {
		t.Fatalf("watch kept ticking after Stop: pings %d -> %d", pingsAfterStop, pingsLater)
	}
}
