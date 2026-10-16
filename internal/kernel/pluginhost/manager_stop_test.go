package pluginhost

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/registry"
)

// TestStopWithTimeout 守超时辅助的四种结局：
// 成功 / 原样返回错误 / 超时 => ErrStopTimeout / timeout<=0 => 一直等。
func TestStopWithTimeout(t *testing.T) {
	t.Run("成功", func(t *testing.T) {
		if err := stopWithTimeout(func() error { return nil }, time.Second); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
	})

	t.Run("原样返回错误", func(t *testing.T) {
		want := errors.New("模块自己报的错")
		err := stopWithTimeout(func() error { return want }, time.Second)
		if !errors.Is(err, want) {
			t.Fatalf("err = %v, want %v", err, want)
		}
	})

	t.Run("超时", func(t *testing.T) {
		start := time.Now()
		err := stopWithTimeout(func() error {
			time.Sleep(200 * time.Millisecond)
			return nil
		}, 20*time.Millisecond)
		if !errors.Is(err, ErrStopTimeout) {
			t.Fatalf("err = %v, want ErrStopTimeout", err)
		}
		if d := time.Since(start); d > 150*time.Millisecond {
			t.Fatalf("超时应在 ~20ms 返回，实际 %v（没有立刻返回就说明实现错了）", d)
		}
	})

	t.Run("timeout<=0 一直等", func(t *testing.T) {
		if err := stopWithTimeout(func() error {
			time.Sleep(30 * time.Millisecond)
			return nil
		}, 0); err != nil {
			t.Fatalf("err = %v, want nil（不设超时应等到 stop 返回）", err)
		}
	})

	t.Run("超时后不泄漏 goroutine", func(t *testing.T) {
		// 弱断言：超时后让 stop 很快返回，稍等片刻再比 goroutine 数（不写脆的阈值）。
		before := runtime.NumGoroutine()
		for i := 0; i < 20; i++ {
			_ = stopWithTimeout(func() error {
				time.Sleep(30 * time.Millisecond)
				return nil
			}, time.Millisecond)
		}
		time.Sleep(120 * time.Millisecond) // 让被超时的 goroutine 全部退出
		after := runtime.NumGoroutine()
		if after > before+5 {
			t.Fatalf("goroutine 可能泄漏：before=%d after=%d", before, after)
		}
	})
}

// TestStopOneUnknownModule 没有该模块进程时必须返回明确错误、且不 panic。
func TestStopOneUnknownModule(t *testing.T) {
	m := &Manager{processes: map[string]*Process{}, states: map[string]string{}}
	err := m.StopOne(context.Background(), registry.Descriptor{ID: "mod.nope"}, time.Second)
	if err == nil {
		t.Fatal("未知模块停止应返回错误")
	}
	if !contains(err.Error(), "mod.nope") {
		t.Errorf("错误信息应含模块 id，got %v", err)
	}
}

// TestStopOneIdempotentWhenStopped 已 stopped 的模块再停应幂等成功。
func TestStopOneIdempotentWhenStopped(t *testing.T) {
	m := &Manager{processes: map[string]*Process{}, states: map[string]string{"mod.a": stateStopped}}
	// 有 states 无 processes 时走"没有已启动的进程"分支；这里补一个占位 Process 以覆盖幂等分支。
	m.processes["mod.a"] = &Process{}
	if err := m.StopOne(context.Background(), registry.Descriptor{ID: "mod.a"}, time.Second); err != nil {
		t.Fatalf("已 stopped 应幂等成功，got %v", err)
	}
}

// TestStartOneMissingBinary 未 Launch 过且二进制不存在 => 返回错误、不 panic。
func TestStartOneMissingBinary(t *testing.T) {
	m := &Manager{
		pluginDir: t.TempDir(),
		processes: map[string]*Process{},
		states:    map[string]string{},
		logger:    nil, // 本路径不应触达日志
	}
	err := m.StartOne(context.Background(),
		registry.Descriptor{ID: "mod.x", Binary: "definitely-not-exist"})
	if err == nil {
		t.Fatal("二进制不存在时应返回错误")
	}
}

// TestRuntimeBackendStatesEmpty RuntimeBackend 在空 Manager 上返回空 map（不是 nil），
// 且未接入 Manager/Registry 时给出明确错误。
func TestRuntimeBackendStatesEmpty(t *testing.T) {
	b := NewRuntimeBackend(&Manager{states: map[string]string{}}, nil, 0)
	if st := b.States(); st == nil || len(st) != 0 {
		t.Fatalf("States() = %v, want 空 map（非 nil）", st)
	}
	if err := b.StartOne(context.Background(), "mod.a"); err == nil {
		t.Error("reg == nil 时 StartOne 应报错")
	}

	var nilBackend *RuntimeBackend
	if st := nilBackend.States(); st == nil {
		t.Error("nil 后端也应返回空 map 而非 nil")
	}
	if err := nilBackend.StopOne(context.Background(), "mod.a"); err == nil {
		t.Error("nil 后端 StopOne 应报错")
	}
}

// TestRuntimeBackendDescriptorMissing 注册表里没有该模块 => 明确错误（含 id）。
func TestRuntimeBackendDescriptorMissing(t *testing.T) {
	reg := registry.New()
	b := NewRuntimeBackend(&Manager{states: map[string]string{}}, reg, time.Second)
	err := b.StopOne(context.Background(), "mod.ghost")
	if err == nil || !contains(err.Error(), "mod.ghost") {
		t.Fatalf("err = %v, want 含 mod.ghost 的错误", err)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
