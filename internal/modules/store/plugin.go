package store

import (
	"flow-monitoring/internal/kernel/config"
	"flow-monitoring/internal/kernel/logging"
	"flow-monitoring/internal/kernel/plugin"
	"flow-monitoring/internal/kernel/registry"
)

// PostgresPlugin 把 PostgreSQL 存储包装成插件。
//
// 提供：storage（storage.Storage）
//
// 降级：PostgreSQL 不可用时 Mount 返回 nil（不注册 storage），
// 依赖 storage 的插件检测到缺失后同样降级，服务仍能启动（仅 transport/health 可用）。
type PostgresPlugin struct {
	pg *Postgres
}

var _ plugin.Plugin = (*PostgresPlugin)(nil)

// Manifest 返回插件元信息。
func (p *PostgresPlugin) Manifest() plugin.Manifest {
	return plugin.Manifest{
		ID:       "modules.store",
		Name:     "PostgreSQL 存储",
		Version:  "1.0.0",
		Layer:    plugin.LayerFoundation,
		Provides: []string{plugin.ServiceStorage},
	}
}

// Mount 连接 PostgreSQL 并建表。
func (p *PostgresPlugin) Mount(ctx *plugin.Context) error {
	cfg := plugin.GetTyped[*config.Config](ctx, plugin.ServiceConfig)
	logger := plugin.GetTyped[*logging.Logger](ctx, plugin.ServiceLogger)
	if cfg == nil {
		return plugin.ErrMissingDependency("config")
	}

	pg, err := New(ctx, cfg.Database.DSN, cfg.Database.MaxConns)
	if err != nil {
		if logger != nil {
			logger.Warn("postgres unavailable, storage disabled", "err", err)
		}
		return nil // 降级：不注册 storage
	}
	if err := pg.Migrate(ctx); err != nil {
		if logger != nil {
			logger.Warn("postgres migrate failed", "err", err)
		}
		pg.Close()
		return nil // 降级
	}

	p.pg = pg
	ctx.Provide(plugin.ServiceStorage, pg)
	return nil
}

// Start 无操作（Mount 已连接）。
func (p *PostgresPlugin) Start(*plugin.Context) error { return nil }

// Stop 关闭连接。
func (p *PostgresPlugin) Stop(*plugin.Context) error {
	if p.pg != nil {
		p.pg.Close()
	}
	return nil
}

func init() {
	registry.Default.MustRegister(&PostgresPlugin{})
}
