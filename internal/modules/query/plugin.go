package query

import (
	"flow-monitoring/internal/kernel/plugin"
	"flow-monitoring/internal/kernel/registry"
	"flow-monitoring/internal/kernel/storage"
	"flow-monitoring/internal/kernel/transport"
)

// QueryPlugin 把 query.Service 包装成插件。
//
// 依赖：modules.store（storage 服务）+ kernel.transport（注册查询路由）
// 提供：query（*Service）
type QueryPlugin struct {
	service *Service
}

var _ plugin.Plugin = (*QueryPlugin)(nil)

// Manifest 返回插件元信息。
func (p *QueryPlugin) Manifest() plugin.Manifest {
	return plugin.Manifest{
		ID:       "modules.query",
		Name:     "查询服务",
		Version:  "1.0.0",
		Layer:    plugin.LayerFoundation,
		Depends:  []string{"modules.store", "kernel.transport"},
		Provides: []string{plugin.ServiceQuery},
	}
}

// Mount 创建查询服务并注册查询路由。
func (p *QueryPlugin) Mount(ctx *plugin.Context) error {
	db := plugin.GetTyped[storage.Storage](ctx, plugin.ServiceStorage)
	if db == nil {
		return nil // 依赖降级
	}
	svc := New(db)
	p.service = svc
	ctx.Provide(plugin.ServiceQuery, svc)

	// 注册查询路由到 transport
	if ts := plugin.GetTyped[*transport.Server](ctx, plugin.ServiceTransport); ts != nil {
		h := svc.Handler()
		ts.Mux().Handle("/api/v1/captures", h)
		ts.Mux().Handle("/api/v1/captures/", h)
	}
	return nil
}

// Start 无操作。
func (p *QueryPlugin) Start(*plugin.Context) error { return nil }

// Stop 无操作。
func (p *QueryPlugin) Stop(*plugin.Context) error { return nil }

func init() {
	registry.Default.MustRegister(&QueryPlugin{})
}
