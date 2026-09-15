package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"flow-monitoring/internal/kernel/config"
	"flow-monitoring/internal/kernel/eventbus"
	"flow-monitoring/internal/kernel/health"
	"flow-monitoring/internal/kernel/lifecycle"
	"flow-monitoring/internal/kernel/logging"
	"flow-monitoring/internal/kernel/registry"
	"flow-monitoring/internal/kernel/transport"
)

// App 应用实例，持有所有内核组件的引用。
//
// 业务模块通过 App 暴露的字段获取共享组件（如 App.EventBus / App.Transport）。
type App struct {
	Cfg       *config.Config
	Logger    *logging.Logger
	LogFile   *os.File
	Registry  *registry.Registry
	Lifecycle *lifecycle.Coordinator
	EventBus  *eventbus.Bus
	Transport *transport.Server
	Health    *health.Health
}

// Bootstrap 创建 App 并装配所有内核组件。
//
// 参数 cfg 与 logger 由调用方提供（便于测试注入）；生产入口由 Run 统一创建。
//
// 装配流程：
//  1. 创建 registry（空）、lifecycle、eventbus
//  2. 创建 transport.Server（尚未监听）
//  3. 创建 health.Health（绑定 registry + lifecycle）
//  4. 注册 /healthz 路由到 transport
//  5. 注册内核模块（transport / health）到 registry
//
// 返回的 App 尚未启动；调用 App.Start 后各模块才真正运行。
func Bootstrap(cfg *config.Config, logger *logging.Logger, logFile *os.File) (*App, error) {
	if cfg == nil {
		cfg = config.Default()
	}
	if logger == nil {
		logger = logging.New(logging.LevelInfo, "json", os.Stdout)
	}

	app := &App{
		Cfg:      cfg,
		Logger:   logger,
		LogFile:  logFile,
		Registry: registry.New(),
		EventBus: eventbus.New(),
	}
	app.Lifecycle = lifecycle.New(app.Registry)

	// transport 未启动前即可注册路由
	app.Transport = transport.New(cfg.Server.HTTPAddr, logger)
	if app.Transport == nil {
		return nil, fmt.Errorf("bootstrap: create transport failed (nil logger)")
	}

	app.Health = health.New(app.Registry, app.Lifecycle)
	app.Transport.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		app.Health.Handler().ServeHTTP(w, r)
	})

	// 注册内核模块
	if err := app.registerKernelModules(); err != nil {
		return nil, err
	}

	return app, nil
}

// Start 启动所有已注册模块（按拓扑序）。
//
// 等价于 app.Lifecycle.StartAll(ctx)。
func (a *App) Start(ctx context.Context) error {
	if err := a.Lifecycle.StartAll(ctx); err != nil {
		a.Logger.Error("bootstrap start failed", "err", err)
		return err
	}
	a.Logger.Info("bootstrap ready", "modules", len(a.Lifecycle.StartedOrder()))
	return nil
}

// Wait 阻塞等待退出信号（SIGINT/SIGTERM）或 ctx 取消，随后优雅关闭。
//
// 退出信号通过 signal.NotifyContext 捕获。
func (a *App) Wait(ctx context.Context) error {
	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	<-sigCtx.Done()
	a.Logger.Info("shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return a.Shutdown(shutdownCtx)
}

// Shutdown 优雅关闭：逆序停模块 → 关闭事件总线 → 关闭日志文件。
func (a *App) Shutdown(ctx context.Context) error {
	a.Logger.Info("bootstrap shutting down")

	// 1. 逆序停止模块（transport 在 StopFn 中 Shutdown）
	if err := a.Lifecycle.StopAll(ctx); err != nil {
		a.Logger.Error("stop modules failed", "err", err)
		// 继续执行后续清理，不中断
	}

	// 2. 关闭事件总线
	a.EventBus.Close()

	// 3. 关闭日志文件
	if a.LogFile != nil {
		if err := a.LogFile.Close(); err != nil {
			a.Logger.Error("close log file failed", "err", err)
		}
	}

	a.Logger.Info("bootstrap stopped")
	return nil
}

// registerKernelModules 注册内核模块到 registry。
//
// 注册的模块：
//   - kernel.transport：HTTP/WS 接待窗口（StartFn 启动监听，StopFn 优雅关闭）
//   - kernel.health：体检报告（仅 HealthFn，无 Start/Stop）
//
// 各模块受 config.Modules 开关控制：未启用则不注册。
func (a *App) registerKernelModules() error {
	if a.Cfg.IsModuleEnabled("transport") {
		err := a.Registry.Register(&registry.ModuleInfo{
			ID:          "kernel.transport",
			Name:        "Transport",
			Description: "HTTP/WebSocket 对外接待窗口",
			Layer:       registry.LayerKernel,
			StartFn: func() error {
				go func() {
					if err := a.Transport.Start(); err != nil {
						a.Logger.Error("transport start failed", "err", err)
					}
				}()
				return nil
			},
			StopFn: func() error {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				return a.Transport.Shutdown(ctx)
			},
			HealthFn: func() registry.HealthStatus {
				if a.Transport.IsStarted() {
					return registry.HealthStatus{Healthy: true}
				}
				return registry.HealthStatus{Healthy: false, Message: "transport not started"}
			},
		})
		if err != nil {
			return fmt.Errorf("bootstrap: register transport: %w", err)
		}
	}

	if a.Cfg.IsModuleEnabled("health") {
		err := a.Registry.Register(&registry.ModuleInfo{
			ID:          "kernel.health",
			Name:        "Health",
			Description: "体检报告聚合器",
			Layer:       registry.LayerKernel,
			HealthFn: func() registry.HealthStatus {
				return registry.HealthStatus{Healthy: true}
			},
		})
		if err != nil {
			return fmt.Errorf("bootstrap: register health: %w", err)
		}
	}

	return nil
}

// Run 全流程便捷入口：读配置 → 建日志 → Bootstrap → Start → Wait。
//
// 供 cmd/server 调用：
//
//	func main() {
//	    if err := bootstrap.Run(""); err != nil {
//	        os.Exit(1)
//	    }
//	}
func Run(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	logger, logFile, err := logging.NewFromConfigFile(
		logging.ParseLevel(cfg.Logging.Level),
		cfg.Logging.Format,
		cfg.Logging.Dir,
		cfg.Logging.FileName,
	)
	if err != nil {
		return err
	}

	app, err := Bootstrap(cfg, logger, logFile)
	if err != nil {
		_ = logFile.Close()
		return err
	}

	if err := app.Start(context.Background()); err != nil {
		return err
	}

	return app.Wait(context.Background())
}
