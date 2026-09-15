package bootstrap

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"flow-monitoring/internal/kernel/config"
	"flow-monitoring/internal/kernel/eventbus"
	"flow-monitoring/internal/kernel/health"
	"flow-monitoring/internal/kernel/lifecycle"
	"flow-monitoring/internal/kernel/logging"
	"flow-monitoring/internal/kernel/plugin"
	"flow-monitoring/internal/kernel/registry"
	"flow-monitoring/internal/kernel/storage"
	"flow-monitoring/internal/kernel/transport"
	"flow-monitoring/internal/modules/importer"
	"flow-monitoring/internal/modules/packetstore"
	"flow-monitoring/internal/modules/query"

	// 匿名 import 触发各模块插件的 init() 自注册到 registry.Default
	_ "flow-monitoring/internal/modules/store"
)

// App 应用实例。
//
// 插件装配完成后，服务字段从 plugin.Context 填充（依赖注入的结果）。
type App struct {
	Cfg       *config.Config
	Logger    *logging.Logger
	LogFile   *os.File
	Context   *plugin.Context
	Registry  *registry.Registry
	Lifecycle *lifecycle.Coordinator
	EventBus  *eventbus.Bus

	// 服务（StartAll 后从 Context 获取，可能为 nil=降级）
	Transport   *transport.Server
	Health      *health.Health
	Storage     storage.Storage
	PacketStore *packetstore.Store
	Importer    *importer.Importer
	Query       *query.Service
}

// Bootstrap 创建 App 并装配内核基础设施。
//
// 流程：
//  1. 创建 plugin.Context，预置 config/logger/eventbus
//  2. 使用 registry.Default（各插件已在 init() 中自注册）
//  3. 创建 lifecycle（registry + Context）
//  4. 预置 registry/lifecycle 到 Context（health 插件依赖）
//
// 注意：不直接创建任何业务模块 —— 模块由各自的插件在 init() 中自注册，
// StartAll 时按拓扑序 Mount（依赖注入）→ Start。
func Bootstrap(cfg *config.Config, logger *logging.Logger, logFile *os.File) (*App, error) {
	if cfg == nil {
		cfg = config.Default()
	}
	if logger == nil {
		logger = logging.New(logging.LevelInfo, "json", os.Stdout)
	}

	// 1. 依赖注入容器 + 基础服务
	ctx := plugin.NewContext(context.Background())
	ctx.Provide(plugin.ServiceConfig, cfg)
	ctx.Provide(plugin.ServiceLogger, logger)

	bus := eventbus.New()
	ctx.Provide(plugin.ServiceEventBus, bus)

	// 2. 注册表（插件已自注册）+ 生命周期
	reg := registry.Default
	lc := lifecycle.New(reg, ctx)
	ctx.Provide(plugin.ServiceRegistry, reg)
	ctx.Provide(plugin.ServiceLifecycle, lc)

	return &App{
		Cfg:       cfg,
		Logger:    logger,
		LogFile:   logFile,
		Context:   ctx,
		Registry:  reg,
		Lifecycle: lc,
		EventBus:  bus,
	}, nil
}

// Start 按拓扑序装配所有插件（Mount → Start），并填充服务字段。
func (a *App) Start(ctx context.Context) error {
	// 装配前做拓扑校验（循环依赖在启动期暴露）
	order, err := a.Registry.TopologicalSort()
	if err != nil {
		a.Logger.Error("plugin topology invalid", "err", err)
		return err
	}
	a.Logger.Info("plugin assembly order", "plugins", order, "count", len(order))

	if err := a.Lifecycle.StartAll(ctx); err != nil {
		a.Logger.Error("bootstrap start failed", "err", err)
		return err
	}

	a.fillServices()
	a.Logger.Info("bootstrap ready", "plugins", len(a.Lifecycle.StartedOrder()))
	return nil
}

// fillServices 从 Context 读取各服务（依赖注入结果）。
func (a *App) fillServices() {
	a.Transport = plugin.GetTyped[*transport.Server](a.Context, plugin.ServiceTransport)
	a.Health = plugin.GetTyped[*health.Health](a.Context, plugin.ServiceHealth)
	a.Storage = plugin.GetTyped[storage.Storage](a.Context, plugin.ServiceStorage)
	a.PacketStore = plugin.GetTyped[*packetstore.Store](a.Context, plugin.ServicePacketStore)
	a.Importer = plugin.GetTyped[*importer.Importer](a.Context, plugin.ServiceImporter)
	a.Query = plugin.GetTyped[*query.Service](a.Context, plugin.ServiceQuery)
}

// Wait 阻塞等待退出信号，随后优雅关闭。
func (a *App) Wait(ctx context.Context) error {
	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	<-sigCtx.Done()
	a.Logger.Info("shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return a.Shutdown(shutdownCtx)
}

// Shutdown 优雅关闭：逆序停插件 → 关事件总线 → 关日志文件。
func (a *App) Shutdown(ctx context.Context) error {
	a.Logger.Info("bootstrap shutting down")

	// 1. 逆序停止插件（transport 在 Stop 中 Shutdown，store 在 Stop 中 Close）
	if err := a.Lifecycle.StopAll(ctx); err != nil {
		a.Logger.Error("stop plugins failed", "err", err)
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

// Run 全流程便捷入口：读配置 → 建日志 → Bootstrap → Start → Wait。
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
