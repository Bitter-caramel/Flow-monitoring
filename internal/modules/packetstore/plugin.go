package packetstore

import (
	"flow-monitoring/internal/kernel/config"
	"flow-monitoring/internal/kernel/plugin"
	"flow-monitoring/internal/kernel/registry"
	"flow-monitoring/internal/kernel/storage"
)

// PacketStorePlugin 把 packetstore.Store 包装成插件。
//
// 依赖：modules.store（storage 服务）
// 提供：packetstore（*Store）
type PacketStorePlugin struct {
	store *Store
}

var _ plugin.Plugin = (*PacketStorePlugin)(nil)

// Manifest 返回插件元信息。
func (p *PacketStorePlugin) Manifest() plugin.Manifest {
	return plugin.Manifest{
		ID:       "modules.packetstore",
		Name:     "原始包文件仓库",
		Version:  "1.0.0",
		Layer:    plugin.LayerFoundation,
		Depends:  []string{"modules.store"},
		Provides: []string{plugin.ServicePacketStore},
	}
}

// Mount 创建文件仓库并注册服务。
func (p *PacketStorePlugin) Mount(ctx *plugin.Context) error {
	// 依赖降级：storage 缺失则不注册
	db := plugin.GetTyped[storage.Storage](ctx, plugin.ServiceStorage)
	if db == nil {
		return nil
	}
	cfg := plugin.GetTyped[*config.Config](ctx, plugin.ServiceConfig)
	dir := "data"
	if cfg != nil && cfg.DataDir != "" {
		dir = cfg.DataDir
	}

	s, err := New(dir, db)
	if err != nil {
		return plugin.ErrMount(err.Error())
	}
	p.store = s
	ctx.Provide(plugin.ServicePacketStore, s)
	return nil
}

// Start 无操作。
func (p *PacketStorePlugin) Start(*plugin.Context) error { return nil }

// Stop 无操作（文件无连接）。
func (p *PacketStorePlugin) Stop(*plugin.Context) error { return nil }

func init() {
	registry.Default.MustRegister(&PacketStorePlugin{})
}
