package transport

import (
	"context"
	"net/http"
	"time"

	"flow-monitoring/internal/kernel/config"
	"flow-monitoring/internal/kernel/health"
	"flow-monitoring/internal/kernel/logging"
	"flow-monitoring/internal/kernel/plugin"
	"flow-monitoring/internal/kernel/registry"
)

// TransportPlugin 把 transport.Server 包装成插件。
//
// 依赖：kernel.health（注册 /healthz 路由）
// 提供：transport（*Server）
type TransportPlugin struct {
	server *Server
}

// 编译期断言实现 plugin.Plugin 与 plugin.HealthChecker。
var (
	_ plugin.Plugin         = (*TransportPlugin)(nil)
	_ plugin.HealthChecker  = (*TransportPlugin)(nil)
)

// Manifest 返回插件元信息。
func (p *TransportPlugin) Manifest() plugin.Manifest {
	return plugin.Manifest{
		ID:       "kernel.transport",
		Name:     "Transport",
		Version:  "1.0.0",
		Layer:    plugin.LayerKernel,
		Depends:  []string{"kernel.health"},
		Provides: []string{plugin.ServiceTransport},
	}
}

// Mount 创建 HTTP 服务器并注册服务。
func (p *TransportPlugin) Mount(ctx *plugin.Context) error {
	cfg := plugin.GetTyped[*config.Config](ctx, plugin.ServiceConfig)
	logger := plugin.GetTyped[*logging.Logger](ctx, plugin.ServiceLogger)
	if cfg == nil || logger == nil {
		return plugin.ErrMissingDependency("config/logger")
	}

	p.server = New(cfg.Server.HTTPAddr, logger)
	if p.server == nil {
		return plugin.ErrMount("create transport server")
	}

	// 注册 /healthz（health 插件已先 Mount，提供 health 服务）
	if h := plugin.GetTyped[*health.Health](ctx, plugin.ServiceHealth); h != nil {
		p.server.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
			h.Handler().ServeHTTP(w, r)
		})
	}

	ctx.Provide(plugin.ServiceTransport, p.server)
	return nil
}

// Start 开始监听（goroutine）。
func (p *TransportPlugin) Start(_ *plugin.Context) error {
	if p.server == nil {
		return plugin.ErrNotMounted
	}
	go func() {
		_ = p.server.Start()
	}()
	return nil
}

// Stop 优雅关闭。
func (p *TransportPlugin) Stop(_ *plugin.Context) error {
	if p.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return p.server.Shutdown(ctx)
}

// Health 返回健康状态。
func (p *TransportPlugin) Health() plugin.HealthStatus {
	if p.server != nil && p.server.IsStarted() {
		return plugin.HealthStatus{Healthy: true}
	}
	return plugin.HealthStatus{Healthy: false, Message: "transport not started"}
}

// Server 返回底层 Server（供其他插件注册路由）。
func (p *TransportPlugin) Server() *Server { return p.server }

func init() {
	registry.Default.MustRegister(&TransportPlugin{})
}
