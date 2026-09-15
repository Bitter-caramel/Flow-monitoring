package importer

import (
	"flow-monitoring/internal/kernel/plugin"
	"flow-monitoring/internal/kernel/registry"
	"flow-monitoring/internal/kernel/transport"
	"flow-monitoring/internal/modules/packetstore"
)

// ImporterPlugin 把 importer.Importer 包装成插件。
//
// 依赖：modules.packetstore（packetstore 服务）+ kernel.transport（注册上传路由）
// 提供：importer（*Importer）
type ImporterPlugin struct {
	importer *Importer
}

var _ plugin.Plugin = (*ImporterPlugin)(nil)

// Manifest 返回插件元信息。
func (p *ImporterPlugin) Manifest() plugin.Manifest {
	return plugin.Manifest{
		ID:       "modules.importer",
		Name:     "流量导入",
		Version:  "1.0.0",
		Layer:    plugin.LayerFoundation,
		Depends:  []string{"modules.packetstore", "kernel.transport"},
		Provides: []string{plugin.ServiceImporter},
	}
}

// Mount 创建导入器并注册上传路由。
func (p *ImporterPlugin) Mount(ctx *plugin.Context) error {
	ps := plugin.GetTyped[*packetstore.Store](ctx, plugin.ServicePacketStore)
	if ps == nil {
		return nil // 依赖降级
	}
	imp := New(ps)
	p.importer = imp
	ctx.Provide(plugin.ServiceImporter, imp)

	// 注册上传路由到 transport
	if ts := plugin.GetTyped[*transport.Server](ctx, plugin.ServiceTransport); ts != nil {
		ts.HandleFunc("POST /api/v1/captures/import", imp.ImportHandler())
	}
	return nil
}

// Start 无操作。
func (p *ImporterPlugin) Start(*plugin.Context) error { return nil }

// Stop 无操作。
func (p *ImporterPlugin) Stop(*plugin.Context) error { return nil }

func init() {
	registry.Default.MustRegister(&ImporterPlugin{})
}
