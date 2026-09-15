package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"flow-monitoring/internal/kernel/plugin"
	"flow-monitoring/internal/kernel/registry"
)

// actionPlugin 记录 Mount/Start/Stop 调用顺序的测试插件。
type actionPlugin struct {
	plugin.Base
	id       string
	depends  []string
	onMount  func() error
	onStart  func() error
	onStop   func() error
}

func (p *actionPlugin) Manifest() plugin.Manifest {
	return plugin.Manifest{ID: p.id, Name: p.id, Version: "1.0.0", Layer: plugin.LayerKernel, Depends: p.depends}
}
func (p *actionPlugin) Mount(*plugin.Context) error {
	if p.onMount != nil {
		return p.onMount()
	}
	return nil
}
func (p *actionPlugin) Start(*plugin.Context) error {
	if p.onStart != nil {
		return p.onStart()
	}
	return nil
}
func (p *actionPlugin) Stop(*plugin.Context) error {
	if p.onStop != nil {
		return p.onStop()
	}
	return nil
}

// TestStartAll_HappyPath 无依赖插件全部 Started。
func TestStartAll_HappyPath(t *testing.T) {
	reg := registry.New()
	var mountCalls, startCalls int32
	_ = reg.Register(&actionPlugin{
		id: "a",
		onMount: func() error { atomic.AddInt32(&mountCalls, 1); return nil },
		onStart: func() error { atomic.AddInt32(&startCalls, 1); return nil },
	})
	_ = reg.Register(&actionPlugin{id: "b"})

	c := New(reg, plugin.NewContext(context.Background()))
	if err := c.StartAll(context.Background()); err != nil {
		t.Fatalf("StartAll: %v", err)
	}
	if got := c.State("a"); got != StateStarted {
		t.Errorf("State(a) = %v, want Started", got)
	}
	if atomic.LoadInt32(&mountCalls) != 1 || atomic.LoadInt32(&startCalls) != 1 {
		t.Errorf("Mount/Start count = %d/%d, want 1/1", mountCalls, startCalls)
	}
}

// TestStartAll_TopologicalOrder 线性依赖按拓扑序装配。
func TestStartAll_TopologicalOrder(t *testing.T) {
	reg := registry.New()
	var trace []string
	var mu sync.Mutex
	mkStart := func(id string) func() error {
		return func() error {
			mu.Lock()
			trace = append(trace, id)
			mu.Unlock()
			return nil
		}
	}
	_ = reg.Register(&actionPlugin{id: "a", depends: []string{"b"}, onStart: mkStart("a")})
	_ = reg.Register(&actionPlugin{id: "b", depends: []string{"c"}, onStart: mkStart("b")})
	_ = reg.Register(&actionPlugin{id: "c", onStart: mkStart("c")})

	c := New(reg, plugin.NewContext(context.Background()))
	if err := c.StartAll(context.Background()); err != nil {
		t.Fatalf("StartAll: %v", err)
	}
	got := fmt.Sprintf("%v", trace)
	if got != "[c b a]" {
		t.Errorf("order = %s, want [c b a]", got)
	}
}

// TestStartAll_MountFailureRollback Mount 失败回滚。
func TestStartAll_MountFailureRollback(t *testing.T) {
	reg := registry.New()
	var stopCalls int32
	_ = reg.Register(&actionPlugin{id: "a", depends: []string{"b"}, onMount: func() error {
		return errors.New("mount failed")
	}})
	_ = reg.Register(&actionPlugin{id: "b", onStop: func() error {
		atomic.AddInt32(&stopCalls, 1)
		return nil
	}})

	c := New(reg, plugin.NewContext(context.Background()))
	err := c.StartAll(context.Background())
	if err == nil {
		t.Fatal("StartAll should fail")
	}
	if got := c.State("a"); got != StateError {
		t.Errorf("State(a) = %v, want Error", got)
	}
}

// TestStopAll_ReverseOrder 关闭按启动逆序。
func TestStopAll_ReverseOrder(t *testing.T) {
	reg := registry.New()
	var trace []string
	var mu sync.Mutex
	mkStop := func(id string) func() error {
		return func() error {
			mu.Lock()
			trace = append(trace, id)
			mu.Unlock()
			return nil
		}
	}
	_ = reg.Register(&actionPlugin{id: "a", depends: []string{"b"}, onStop: mkStop("a")})
	_ = reg.Register(&actionPlugin{id: "b", depends: []string{"c"}, onStop: mkStop("b")})
	_ = reg.Register(&actionPlugin{id: "c", onStop: mkStop("c")})

	c := New(reg, plugin.NewContext(context.Background()))
	_ = c.StartAll(context.Background())
	if err := c.StopAll(context.Background()); err != nil {
		t.Fatalf("StopAll: %v", err)
	}
	got := fmt.Sprintf("%v", trace)
	if got != "[a b c]" {
		t.Errorf("stop order = %s, want [a b c]", got)
	}
}

// TestStopAll_ContinuesOnError 某插件关闭失败其他继续。
func TestStopAll_ContinuesOnError(t *testing.T) {
	reg := registry.New()
	var bStops int32
	_ = reg.Register(&actionPlugin{id: "a", depends: []string{"b"}, onStop: func() error {
		return errors.New("stop a failed")
	}})
	_ = reg.Register(&actionPlugin{id: "b", onStop: func() error {
		atomic.AddInt32(&bStops, 1)
		return nil
	}})

	c := New(reg, plugin.NewContext(context.Background()))
	_ = c.StartAll(context.Background())
	if err := c.StopAll(context.Background()); err == nil {
		t.Fatal("StopAll should return error from a")
	}
	if atomic.LoadInt32(&bStops) != 1 {
		t.Errorf("b should still be stopped: %d", bStops)
	}
}

// TestState_String 状态名。
func TestState_String(t *testing.T) {
	cases := map[State]string{
		StateCreated:  "Created",
		StateMounting: "Mounting",
		StateMounted:  "Mounted",
		StateStarting: "Starting",
		StateStarted:  "Started",
		StateStopping: "Stopping",
		StateStopped:  "Stopped",
		StateError:    "Error",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("State(%d).String() = %q, want %q", s, got, want)
		}
	}
}
