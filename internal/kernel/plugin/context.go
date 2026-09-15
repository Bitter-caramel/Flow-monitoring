package plugin

import (
	"context"
	"sync"
)

// 内置服务名常量（Context 中的 key）。
//
// bootstrap 预置 config/logger/eventbus；各模块 Mount 时注册自己的服务。
const (
	ServiceConfig      = "config"
	ServiceLogger      = "logger"
	ServiceEventBus    = "eventbus"
	ServiceRegistry    = "registry"
	ServiceLifecycle   = "lifecycle"
	ServiceStorage     = "storage"
	ServicePacketStore = "packetstore"
	ServiceImporter    = "importer"
	ServiceQuery       = "query"
	ServiceTransport   = "transport"
	ServiceHealth      = "health"
)

// Context 插件挂载上下文（依赖注入容器）。
//
// 线程安全；同时实现 context.Context（嵌入），可直接传给需要
// context.Context 的下游（如 store.New 的数据库连接）。
// bootstrap 创建 Context 并预置基础服务（config/logger/eventbus）；
// 插件在 Mount 阶段用 Provide 注册自己的服务、用 Get 获取依赖的服务。
type Context struct {
	context.Context
	mu       sync.RWMutex
	services map[string]any
}

// NewContext 创建上下文（base 为底层 context，nil 用 Background）。
func NewContext(base context.Context) *Context {
	if base == nil {
		base = context.Background()
	}
	return &Context{Context: base, services: make(map[string]any)}
}

// Provide 注册一个服务（覆盖已存在的同名服务，实现可替换）。
func (c *Context) Provide(name string, svc any) {
	if name == "" || svc == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.services[name] = svc
}

// Get 获取服务；不存在返回 nil。
func (c *Context) Get(name string) any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.services[name]
}

// Has 判断服务是否已注册。
func (c *Context) Has(name string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.services[name]
	return ok
}

// GetTyped 泛型获取服务（类型不符返回零值）。
//
// 用法：logger := plugin.GetTyped[*logging.Logger](ctx, plugin.ServiceLogger)
func GetTyped[T any](c *Context, name string) T {
	v := c.Get(name)
	if v == nil {
		var zero T
		return zero
	}
	if t, ok := v.(T); ok {
		return t
	}
	var zero T
	return zero
}
