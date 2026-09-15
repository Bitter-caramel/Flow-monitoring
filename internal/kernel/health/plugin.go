package health

import (
	"flow-monitoring/internal/kernel/lifecycle"
	"flow-monitoring/internal/kernel/plugin"
	"flow-monitoring/internal/kernel/registry"
)

// HealthPlugin 把 health.Health 包装成插件。
//
// 依赖：registry + lifecycle（基础服务，bootstrap 预置）
// 提供：health（*Health）
type HealthPlugin struct {
	health *Health
}

var _ plugin.Plugin = (*HealthPlugin)(nil)

// Manifest 返回插件元信息。
func (p *HealthPlugin) Manifest() plugin.Manifest {
	return plugin.Manifest{
		ID:       "kernel.health",
		Name:     "Health",
		Version:  "1.0.0",
		Layer:    plugin.LayerKernel,
		Provides: []string{plugin.ServiceHealth},
	}
}

// Mount 创建健康聚合器并注册服务。
func (p *HealthPlugin) Mount(ctx *plugin.Context) error {
	reg := plugin.GetTyped[*registry.Registry](ctx, plugin.ServiceRegistry)
	lc := plugin.GetTyped[*lifecycle.Coordinator](ctx, plugin.ServiceLifecycle)
	if reg == nil || lc == nil {
		return plugin.ErrMissingDependency("registry/lifecycle")
	}
	p.health = New(reg, lc)
	ctx.Provide(plugin.ServiceHealth, p.health)
	return nil
}

// Start 无操作（健康聚合器被动响应）。
func (p *HealthPlugin) Start(*plugin.Context) error { return nil }

// Stop 无操作。
func (p *HealthPlugin) Stop(*plugin.Context) error { return nil }

// Health 返回自身健康。
func (p *HealthPlugin) Health() plugin.HealthStatus {
	if p.health != nil {
		return plugin.HealthStatus{Healthy: true}
	}
	return plugin.HealthStatus{Healthy: false, Message: "health not mounted"}
}

func init() {
	registry.Default.MustRegister(&HealthPlugin{})
}
