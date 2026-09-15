package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"flow-monitoring/internal/kernel/registry"
)

// TestStartAll_HappyPath 三个无依赖模块全部 Started。
func TestStartAll_HappyPath(t *testing.T) {
	reg := registry.New()
	var aInits, aStarts, aStops int32
	_ = reg.Register(&registry.ModuleInfo{
		ID:       "a",
		InitFn:   func() error { atomic.AddInt32(&aInits, 1); return nil },
		StartFn:  func() error { atomic.AddInt32(&aStarts, 1); return nil },
		StopFn:   func() error { atomic.AddInt32(&aStops, 1); return nil },
	})
	_ = reg.Register(&registry.ModuleInfo{ID: "b"})
	_ = reg.Register(&registry.ModuleInfo{ID: "c"})

	c := New(reg)
	if err := c.StartAll(context.Background()); err != nil {
		t.Fatalf("StartAll: %v", err)
	}
	if got := c.State("a"); got != StateStarted {
		t.Errorf("State(a) = %v, want Started", got)
	}
	if got := c.State("b"); got != StateStarted {
		t.Errorf("State(b) = %v, want Started", got)
	}
	if atomic.LoadInt32(&aInits) != 1 || atomic.LoadInt32(&aStarts) != 1 {
		t.Errorf("Init/Start count: init=%d start=%d, want 1/1", aInits, aStarts)
	}
	// 尚未 StopAll，Stop 应为 0
	if atomic.LoadInt32(&aStops) != 0 {
		t.Errorf("Stop count: %d, want 0", aStops)
	}
}

// TestStartAll_TopologicalOrder 线性依赖按拓扑序启动。
func TestStartAll_TopologicalOrder(t *testing.T) {
	reg := registry.New()
	// a→b→c：期望启动顺序 c, b, a
	var trace []string
	var mu sync.Mutex
	mkFn := func(id string) func() error {
		return func() error {
			mu.Lock()
			trace = append(trace, id)
			mu.Unlock()
			return nil
		}
	}
	_ = reg.Register(&registry.ModuleInfo{ID: "a", Depends: []registry.ModuleID{"b"}, StartFn: mkFn("a")})
	_ = reg.Register(&registry.ModuleInfo{ID: "b", Depends: []registry.ModuleID{"c"}, StartFn: mkFn("b")})
	_ = reg.Register(&registry.ModuleInfo{ID: "c", StartFn: mkFn("c")})

	c := New(reg)
	if err := c.StartAll(context.Background()); err != nil {
		t.Fatalf("StartAll: %v", err)
	}
	got := fmt.Sprintf("%v", trace)
	want := "[c b a]"
	if got != want {
		t.Errorf("order = %s, want %s", got, want)
	}
}

// TestStartAll_FailureRollback 启动失败时回滚已启动模块。
func TestStartAll_FailureRollback(t *testing.T) {
	reg := registry.New()
	// c → b → a，a 启动失败，c/b 应已启动并被回滚关闭
	var cStops int32
	_ = reg.Register(&registry.ModuleInfo{ID: "a", Depends: []registry.ModuleID{"b"}, StartFn: func() error {
		return errors.New("simulated failure")
	}})
	_ = reg.Register(&registry.ModuleInfo{
		ID:       "b",
		Depends:  []registry.ModuleID{"c"},
		StartFn:  func() error { return nil },
		StopFn:   func() error { atomic.AddInt32(&cStops, 1); return nil },
	})
	_ = reg.Register(&registry.ModuleInfo{
		ID:       "c",
		StartFn:  func() error { return nil },
		StopFn:   func() error { atomic.AddInt32(&cStops, 1); return nil },
	})

	c := New(reg)
	err := c.StartAll(context.Background())
	if err == nil {
		t.Fatal("StartAll should fail")
	}
	if got := c.State("a"); got != StateError {
		t.Errorf("State(a) = %v, want Error", got)
	}
	if got := c.State("b"); got != StateStopped {
		t.Errorf("State(b) = %v, want Stopped (rolled back)", got)
	}
	if got := c.State("c"); got != StateStopped {
		t.Errorf("State(c) = %v, want Stopped (rolled back)", got)
	}
	if atomic.LoadInt32(&cStops) != 2 {
		t.Errorf("Stop count: %d, want 2 (b and c rolled back)", cStops)
	}
}

// TestStopAll_ReverseOrder 关闭按启动逆序。
func TestStopAll_ReverseOrder(t *testing.T) {
	reg := registry.New()
	var trace []string
	var mu sync.Mutex
	mkFn := func(id string) func() error {
		return func() error {
			mu.Lock()
			trace = append(trace, id)
			mu.Unlock()
			return nil
		}
	}
	_ = reg.Register(&registry.ModuleInfo{ID: "a", Depends: []registry.ModuleID{"b"}, StopFn: mkFn("a")})
	_ = reg.Register(&registry.ModuleInfo{ID: "b", Depends: []registry.ModuleID{"c"}, StopFn: mkFn("b")})
	_ = reg.Register(&registry.ModuleInfo{ID: "c", StopFn: mkFn("c")})

	c := New(reg)
	if err := c.StartAll(context.Background()); err != nil {
		t.Fatalf("StartAll: %v", err)
	}
	// reset trace before StopAll
	trace = nil
	if err := c.StopAll(context.Background()); err != nil {
		t.Fatalf("StopAll: %v", err)
	}
	got := fmt.Sprintf("%v", trace)
	want := "[a b c]" // 启动是 c,b,a，关闭逆序是 a,b,c
	if got != want {
		t.Errorf("stop order = %s, want %s", got, want)
	}
}

// TestStopAll_ContinuesOnError 某模块关闭失败时其他模块仍被关闭。
func TestStopAll_ContinuesOnError(t *testing.T) {
	reg := registry.New()
	var bStops int32
	_ = reg.Register(&registry.ModuleInfo{ID: "a", Depends: []registry.ModuleID{"b"}, StopFn: func() error {
		return errors.New("stop a failed")
	}})
	_ = reg.Register(&registry.ModuleInfo{ID: "b", StopFn: func() error {
		atomic.AddInt32(&bStops, 1)
		return nil
	}})

	c := New(reg)
	if err := c.StartAll(context.Background()); err != nil {
		t.Fatalf("StartAll: %v", err)
	}
	err := c.StopAll(context.Background())
	if err == nil {
		t.Fatal("StopAll should return error from a")
	}
	if atomic.LoadInt32(&bStops) != 1 {
		t.Errorf("b should still be stopped despite a's failure: %d", bStops)
	}
	if got := c.State("b"); got != StateStopped {
		t.Errorf("State(b) = %v, want Stopped", got)
	}
	if got := c.State("a"); got != StateStopped {
		t.Errorf("State(a) = %v, want Stopped (still marked stopped despite error)", got)
	}
}

// TestStartAll_CtxCancel 启动期 ctx 取消时回滚已启动模块。
//
// 这里用同步 StartFn 模拟取消发生在第一个模块启动之前；
// 实际生产场景下 ctx 取消常来自超时。
func TestStartAll_CtxCancel(t *testing.T) {
	reg := registry.New()
	var stopCount int32
	_ = reg.Register(&registry.ModuleInfo{
		ID: "a",
		StopFn: func() error { atomic.AddInt32(&stopCount, 1); return nil },
	})
	_ = reg.Register(&registry.ModuleInfo{ID: "b"})

	c := New(reg)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	err := c.StartAll(ctx)
	if err == nil {
		t.Fatal("StartAll should fail with ctx canceled")
	}
	// ctx 取消时无任何模块被启动 → 无需回滚，stopCount 应为 0
	if atomic.LoadInt32(&stopCount) != 0 {
		t.Errorf("stop count = %d, want 0 (no module started)", stopCount)
	}
}

// TestState_String 状态名输出。
func TestState_String(t *testing.T) {
	cases := map[State]string{
		StateCreated:      "Created",
		StateInitializing: "Initializing",
		StateInitialized:  "Initialized",
		StateStarting:     "Starting",
		StateStarted:      "Started",
		StateStopping:     "Stopping",
		StateStopped:      "Stopped",
		StateError:        "Error",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("State(%d).String() = %q, want %q", s, got, want)
		}
	}
}

// TestCoordinator_Errs 启动失败后错误被记录。
func TestCoordinator_Errs(t *testing.T) {
	reg := registry.New()
	want := errors.New("boom")
	_ = reg.Register(&registry.ModuleInfo{ID: "a", StartFn: func() error { return want }})

	c := New(reg)
	_ = c.StartAll(context.Background())
	errs := c.Errs()
	if errs["a"] == nil {
		t.Errorf("errs[a] should not be nil")
	}
}

