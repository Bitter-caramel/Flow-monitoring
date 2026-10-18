// Package bootstrap 是平台的总开机按钮（L0 内核）。
//
// 职责：读配置 → 建日志 → 起进程内基础设施（事件总线/存储/原始文件仓库）
// → 起模块进程管理器与宿主桥接 → 读模块清单 → 起 HTTP 网关
// → 按拓扑序启动模块进程 → ready。
//
// 关键设计（修正旧版）：内核不再 import 任何业务模块。模块清单完全来自
// registry/backend-modules/*.json，每个文件用 enabled 字段声明自己是否参与装配；
// 模块以独立进程运行，内核只通过 pkg/plugin 契约与它们通信。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"flow-monitoring/internal/kernel/alerting"
	"flow-monitoring/internal/kernel/config"
	"flow-monitoring/internal/kernel/eventbus"
	"flow-monitoring/internal/kernel/health"
	"flow-monitoring/internal/kernel/logging"
	"flow-monitoring/internal/kernel/modulecontrol"
	"flow-monitoring/internal/kernel/pluginhost"
	"flow-monitoring/internal/kernel/registry"
	"flow-monitoring/internal/kernel/storage"
	"flow-monitoring/internal/kernel/transport"
	"flow-monitoring/internal/modules/store"
)

// detectFeatureTopic 是 capture 进程发布检测告警的事件主题（跨进程契约）。
const detectFeatureTopic = "detect.feature"

// App 应用实例（进程内基础设施 + 模块进程管理器）。
type App struct {
	Cfg          *config.Config
	Logger       *logging.Logger
	LogFile      *os.File
	Bus          *eventbus.Bus
	Storage      storage.Storage
	Registry     *registry.Registry
	Manager      *pluginhost.Manager
	Health       *health.Health
	Transport    *transport.Server
	Alerts       *alerting.Service
	storageWatch *storageWatch
}

// Bootstrap 创建 App 并装配进程内基础设施。
//
// 注意：不 import、不创建任何业务模块——业务模块由 registry 清单声明，
// Manager 按拓扑序以独立进程启动（对应架构 v0.3 P1「内核最小化」）。
func Bootstrap(cfg *config.Config, logger *logging.Logger, logFile *os.File) (*App, error) {
	if cfg == nil {
		cfg = config.Default()
	}
	if logger == nil {
		logger = logging.New(logging.LevelInfo, "json", os.Stdout)
	}

	// ★ 控制面红线（设计文档 §6.3）：非回环监听必须配置 Token，否则拒绝启动。
	if err := config.ValidateListenAuth(cfg.Server.HTTPAddr, cfg.Auth.Token); err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}

	bus := eventbus.New()

	// 存储：进程内基础设施（db-adapter），不可用则降级（模块经 Host 桥访问时返回空）
	var db storage.Storage
	pg, err := store.New(context.Background(), cfg.Database.DSN, cfg.Database.MaxConns)
	if err == nil {
		if err := pg.Migrate(context.Background()); err == nil {
			db = pg
		} else {
			_ = pg.Close()
			logger.Warn("db migrate failed, storage disabled", "err", err)
		}
	} else {
		logger.Warn("db unavailable, storage disabled", "err", err)
	}

	// 宿主桥接 + 模块进程管理器
	bridge := pluginhost.NewBridge(cfg, logger, bus, db)

	// 存储巡检：每 10s 检查一次；断了自动重连、恢复后自动接回（不重启后端）。
	// 用 seed 把启动时已打开的句柄交给巡检，首次 tick 只 Ping 不重复 Open。
	watch := newStorageWatch(
		&pgProbe{dsn: cfg.Database.DSN, maxConns: cfg.Database.MaxConns},
		bridge.SetDB,
		logger,
	)
	watch.seed(db)

	mgr := pluginhost.NewManager(cfg.PluginDir, cfg, logger, bridge)
	if err := mgr.Start(); err != nil {
		return nil, fmt.Errorf("bootstrap: plugin manager: %w", err)
	}

	// 模块清单：完全来自声明式注册表目录（registry/backend-modules/*.json）。
	// 加/删/换模块 = 加/删/换一个 json + 一个二进制，内核代码零改动；
	// 停用模块 = 把该 json 的 enabled 改成 false（仍留在目录里，可见可查）。
	reg := registry.New()
	if cfg.ManifestDir == "" {
		logger.Warn("manifest_dir is empty, no module will be loaded")
	} else {
		loaded, err := registry.Load(cfg.ManifestDir)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: load module registry %s: %w", cfg.ManifestDir, err)
		}
		for _, d := range loaded.List() {
			if err := reg.Register(d); err != nil {
				return nil, fmt.Errorf("bootstrap: register module %s: %w", d.ID, err)
			}
		}
		logger.Info("module registry loaded",
			"dir", cfg.ManifestDir,
			"declared", len(loaded.List()),
			"enabled", len(loaded.ListEnabled()))
	}

	// 启动任何模块之前做一次纯函数自检：Error 阻塞启动，Warning 只记录日志。
	rep := reg.SelfCheck()
	for _, w := range rep.Warnings {
		logger.Warn("module self-check", "code", w.Code, "module", w.ModuleID, "msg", w.Message)
	}
	if !rep.OK {
		return nil, fmt.Errorf("bootstrap: 模块自检未通过（%d 项错误）：%s", len(rep.Errors), summarize(rep.Errors))
	}

	h := health.New(mgr)

	ts := transport.New(cfg.Server.HTTPAddr, logger)
	ts.SetAPIToken(cfg.Auth.Token)
	ts.SetGatewayResolver(bridge.Resolve)
	ts.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		// 在既有健康报告后追加 storage 字段，让"存储降级被看见"。
		rep := h.Report()
		code := http.StatusOK
		if rep.Status == health.StatusDown {
			code = http.StatusServiceUnavailable
		}
		body := struct {
			health.Report
			Storage StorageHealth `json:"storage"`
		}{
			Report:  rep,
			Storage: watch.HealthView(),
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(body)
	})
	ts.SetStaticDir(cfg.StaticDir)

	// 控制面：唯一行为实现（modulecontrol）+ 运行期后端（pluginhost，StopTimeout<=0 用默认值）。
	// 此时 reg 与 mgr 均已建好（mgr 在上方 Start、reg 在清单加载处），故在此注入。
	mctl, err := modulecontrol.New(modulecontrol.Options{
		ManifestDir: cfg.ManifestDir,
		Logger:      logger,
		// 与 pluginhost.Manager.Launch 完全相同的拼路径规则：
		// PluginDir + 清单 binary（Windows 再加 .exe）。只做只读 os.Stat。
		BinaryChecker: func(binary string) bool {
			bin := filepath.Join(cfg.PluginDir, binary)
			if runtime.GOOS == "windows" {
				bin += ".exe"
			}
			_, statErr := os.Stat(bin)
			return statErr == nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("bootstrap: module control: %w", err)
	}
	mctl = mctl.WithRuntime(pluginhost.NewRuntimeBackend(mgr, reg, 0))

	// 控制面审计：写 logs/audit.jsonl（一行一条 JSON）。
	// 构造失败只告警并关闭审计，不影响启动与主流程。
	auditDir := cfg.Logging.Dir
	if auditDir == "" {
		auditDir = "logs"
	}
	auditSink, err := modulecontrol.NewFileAuditSink(filepath.Join(auditDir, "audit.jsonl"))
	if err != nil {
		logger.Warn("audit sink disabled", "err", err)
	} else {
		mctl = mctl.WithAuditSink(auditSink)
	}

	transport.RegisterModulesAPI(ts, mctl)

	// 宿主侧 alerting（任务 15-2b）：只订阅事件总线，不加载规则、不跑热路径。
	// ★ 只追加/替换装配，不改既有模块启动顺序；解析失败由 Service 内部计数 + 日志。
	alerts := alerting.New(alerting.Config{
		Capacity: cfg.Detect.AlertBuffer,
		Logger:   logger.Logger,
	})
	alerts.Register(ts)

	return &App{
		Cfg:          cfg,
		Logger:       logger,
		LogFile:      logFile,
		Bus:          bus,
		Storage:      db,
		Registry:     reg,
		Manager:      mgr,
		Health:       h,
		Transport:    ts,
		Alerts:       alerts,
		storageWatch: watch,
	}, nil
}

// Start 按拓扑序启动模块进程，然后起 HTTP 网关。
func (a *App) Start(ctx context.Context) error {
	// 存储巡检：随应用生命周期启动（立即跑一次，此后每 10s）。
	if a.storageWatch != nil {
		a.storageWatch.Start(ctx)
	}

	// ★ 先订阅 detect.feature 再启动模块：模块一启动可能立刻回放，
	//   提前订阅才不会漏掉最早的几条告警。
	if a.Alerts != nil {
		a.Alerts.Start(a.Bus, detectFeatureTopic)
	}

	order, err := a.Registry.TopologicalSort()
	if err != nil {
		a.Logger.Error("module topology invalid", "err", err)
		return err
	}
	a.Logger.Info("module assembly order", "modules", descriptorIDs(order), "count", len(order))

	for _, d := range order {
		if err := a.Manager.Launch(d); err != nil {
			// 缺二进制/握手失败：告警并跳过（优雅降级，服务仍可用）
			a.Logger.Warn("module launch failed (skipped)", "id", d.ID, "err", err)
		}
	}
	if err := a.Manager.StartAll(order); err != nil {
		a.Logger.Error("module start failed", "err", err)
		return err
	}

	go func() { _ = a.Transport.Start() }()
	a.Logger.Info("bootstrap ready", "modules", len(order))
	return nil
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

// Shutdown 优雅关闭：逆序停模块进程 → 关事件总线 → 关日志文件。
func (a *App) Shutdown(ctx context.Context) error {
	a.Logger.Info("bootstrap shutting down")

	// 先停宿主侧 alerting 订阅（Stop 幂等、会等待消费 goroutine 退出）。
	if a.Alerts != nil {
		a.Alerts.Stop()
	}

	if err := a.Transport.Shutdown(ctx); err != nil {
		a.Logger.Error("transport shutdown", "err", err)
	}
	if err := a.Manager.StopAll(ctx); err != nil {
		a.Logger.Error("stop modules", "err", err)
	}
	// 先停巡检（取消 + 等待退出），再关闭它当前持有的最新存储句柄。
	if a.storageWatch != nil {
		a.storageWatch.Stop()
		if db := a.storageWatch.currentDB(); db != nil {
			_ = db.Close()
		}
	} else if a.Storage != nil {
		_ = a.Storage.Close()
	}
	a.Bus.Close()
	if a.LogFile != nil {
		_ = a.LogFile.Close()
	}
	a.Logger.Info("bootstrap stopped")
	return nil
}

// Run 全流程便捷入口：读配置 → 建日志 → Bootstrap → Start → Wait。
// Run 函数是应用程序的入口点，负责初始化并启动应用程序
// 参数:
//   - cfgPath: 配置文件的路径
// 返回值:
//   - error: 如果初始化或启动过程中发生错误，则返回错误信息
/*
 * Run 函数是应用程序的入口点，它负责加载配置、初始化日志系统、启动应用并等待应用结束
 * @param cfgPath 配置文件的路径
 * @return error 如果在执行过程中出现错误，则返回错误信息
 */
func Run(cfgPath string) error {
	// 从指定路径加载配置文件
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	// 根据配置文件中的日志设置创建日志记录器和日志文件
	logger, logFile, err := logging.NewFromConfigFile(
		logging.ParseLevel(cfg.Logging.Level), // 解析日志级别
		cfg.Logging.Format,                    // 日志格式
		cfg.Logging.Dir,
		cfg.Logging.FileName, // 日志文件名
	)
	if err != nil {
		return err
	}

	// 使用配置、日志记录器和日志文件引导应用程序启动
	app, err := Bootstrap(cfg, logger, logFile)
	if err != nil {
		_ = logFile.Close() // 如果启动失败，关闭日志文件
		return err
	}

	// 启动应用程序并传入上下文
	if err := app.Start(context.Background()); err != nil {
		return err
	}

	// 等待应用程序结束
	return app.Wait(context.Background())
}

// descriptorIDs 接收一个registry.Descriptor类型的切片，返回一个包含所有描述符ID的字符串切片
func descriptorIDs(ds []registry.Descriptor) []string {
	// 创建一个与输入切片长度相同的字符串切片，用于存储ID
	ids := make([]string, len(ds))
	for i, d := range ds {
		ids[i] = d.ID
	}
	return ids
}

// summarize 把自检 Issue 拼成一行日志用摘要：`code(module)` 形式，最多前 5 条，
// 超出部分以 `...(+N more)` 收尾。无 ModuleID 的（如 core_missing/topology_error）只写 code。
func summarize(issues []registry.Issue) string {
	const maxIssues = 5
	parts := make([]string, 0, len(issues)+1)
	for i, is := range issues {
		if i >= maxIssues {
			parts = append(parts, fmt.Sprintf("...(+%d more)", len(issues)-maxIssues))
			break
		}
		if is.ModuleID != "" {
			parts = append(parts, fmt.Sprintf("%s(%s)", is.Code, is.ModuleID))
			continue
		}
		parts = append(parts, is.Code)
	}
	return strings.Join(parts, "; ")
}
