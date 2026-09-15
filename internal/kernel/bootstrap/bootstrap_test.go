package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/config"
	"flow-monitoring/internal/kernel/logging"
	"flow-monitoring/internal/kernel/registry"
)

// newTestApp 创建测试 App（transport 监听 :0，日志到 buffer）。
func newTestApp(t *testing.T) *App {
	t.Helper()
	cfg := config.Default()
	cfg.Server.HTTPAddr = ":0" // 系统分配随机端口，避免端口冲突

	logger := logging.New(logging.LevelInfo, "json", os.Stdout)
	app, err := Bootstrap(cfg, logger, nil)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	return app
}

// TestBootstrap_Assemble 装配正确性：核心组件非 nil，内核模块已注册。
func TestBootstrap_Assemble(t *testing.T) {
	app := newTestApp(t)

	if app.Registry == nil || app.Lifecycle == nil || app.EventBus == nil ||
		app.Transport == nil || app.Health == nil {
		t.Fatal("core components should not be nil")
	}

	// transport 与 health 模块应已注册
	if _, ok := app.Registry.Get("kernel.transport"); !ok {
		t.Error("kernel.transport should be registered")
	}
	if _, ok := app.Registry.Get("kernel.health"); !ok {
		t.Error("kernel.health should be registered")
	}

	// 拓扑排序应无环
	if _, err := app.Registry.TopologicalSort(); err != nil {
		t.Errorf("TopologicalSort: %v", err)
	}
}

// TestBootstrap_HealthzRoute /healthz 在模块启动后返回 ok。
func TestBootstrap_HealthzRoute(t *testing.T) {
	app := newTestApp(t)

	// 先启动模块（transport 在 goroutine 监听 :0）
	if err := app.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = app.Shutdown(ctx)
	}()

	// 用 handler 测试路由（不依赖真实监听端口）
	ts := httptest.NewServer(app.Transport.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	var rep map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rep["status"] != "ok" {
		t.Errorf("status = %v, want ok", rep["status"])
	}
}

// TestBootstrap_StartAndShutdown 完整启动 + 优雅关闭。
func TestBootstrap_StartAndShutdown(t *testing.T) {
	app := newTestApp(t)

	ctx := context.Background()
	if err := app.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// 等 transport goroutine 开始监听
	time.Sleep(100 * time.Millisecond)

	// 所有内核模块应 Started
	for _, id := range []string{"kernel.transport", "kernel.health"} {
		st := app.Lifecycle.State(registry.ModuleID(id))
		if st.String() != "Started" {
			t.Errorf("module %s state = %s, want Started", id, st)
		}
	}

	// 优雅关闭
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := app.Shutdown(shutdownCtx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}

	// transport 应已停止
	if app.Transport.IsStarted() {
		t.Error("transport should be stopped after Shutdown")
	}
}

// TestBootstrap_ModuleToggle 模块开关：禁用 health 后不注册。
func TestBootstrap_ModuleToggle(t *testing.T) {
	cfg := config.Default()
	cfg.Server.HTTPAddr = ":0"
	cfg.Modules["health"] = false // 显式禁用 health

	logger := logging.New(logging.LevelInfo, "json", os.Stdout)
	app, err := Bootstrap(cfg, logger, nil)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	if _, ok := app.Registry.Get("kernel.health"); ok {
		t.Error("kernel.health should NOT be registered when disabled")
	}
	if _, ok := app.Registry.Get("kernel.transport"); !ok {
		t.Error("kernel.transport should still be registered")
	}
}
