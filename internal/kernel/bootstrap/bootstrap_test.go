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
)

// newTestApp 创建测试 App（transport 监听 :0，日志到 stdout）。
func newTestApp(t *testing.T) *App {
	t.Helper()
	cfg := config.Default()
	cfg.Server.HTTPAddr = ":0"
	cfg.Database.DSN = "postgres://invalid:invalid@127.0.0.1:59999/none?sslmode=disable" // 必定失败，测试降级

	logger := logging.New(logging.LevelInfo, "json", os.Stdout)
	app, err := Bootstrap(cfg, logger, nil)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	return app
}

// TestBootstrap_Assemble 基础设施装配正确。
func TestBootstrap_Assemble(t *testing.T) {
	app := newTestApp(t)
	if app.Context == nil || app.Registry == nil || app.Lifecycle == nil || app.EventBus == nil {
		t.Fatal("core components should not be nil")
	}
	// 插件已在 init 自注册，注册表应非空
	if len(app.Registry.List()) == 0 {
		t.Error("registry should contain self-registered plugins")
	}
	// 拓扑校验应通过
	if _, err := app.Registry.TopologicalSort(); err != nil {
		t.Errorf("TopologicalSort: %v", err)
	}
}

// TestBootstrap_StartAndShutdown 完整装配 + 优雅关闭。
func TestBootstrap_StartAndShutdown(t *testing.T) {
	app := newTestApp(t)

	if err := app.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	// transport 已装配（从 Context 填充）
	if app.Transport == nil {
		t.Error("Transport should be wired after Start")
	}
	if app.Health == nil {
		t.Error("Health should be wired after Start")
	}
	// storage 降级（DSN 无效），应为 nil
	if app.Storage != nil {
		t.Error("Storage should be nil (degraded) when PG unavailable")
	}

	// 优雅关闭
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := app.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

// TestBootstrap_HealthzRoute healthz 通过 handler 返回 ok（模块已装配）。
func TestBootstrap_HealthzRoute(t *testing.T) {
	app := newTestApp(t)
	if err := app.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = app.Shutdown(ctx)
	}()

	// healthz 路由注册在 transport，通过 handler 测试
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
	// 状态可能是 ok 或 degraded（取决于插件装配），但必须是 JSON
	if _, ok := rep["status"]; !ok {
		t.Error("response should contain status field")
	}
}
