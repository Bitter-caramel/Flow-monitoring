package plugin

import (
	hplugin "github.com/hashicorp/go-plugin"
	"net/rpc"
)

// ModulePluginName go-plugin 注册表中模块接口的服务名。
// 宿主与模块进程必须一致（客户端按此名调用远程方法）。
const ModulePluginName = "module"

// rpcServiceName go-plugin 内部把插件实现固定注册成的 net/rpc 服务名。
//
// 注意：这个名字由 go-plugin 写死为 "Plugin"（见其 rpc_server.go 的
// RegisterName("Plugin", impl)），与 Plugins map 的 key 无关。
// 客户端必须按 "Plugin.<Method>" 调用，否则报 "can't find service"。
const rpcServiceName = "Plugin"

// Module 是模块进程对宿主暴露的生命周期接口（跨进程契约）。
//
// 每个模块进程的 main() 通过 ServeModule 把实现暴露给宿主；
// 宿主通过 ModulePlugin 拿到一个客户端代理（moduleRPCClient）远程调用。
//
// 生命周期（由宿主按依赖拓扑序驱动）：
//   Start：模块读取配置快照、监听 FLOW_MODULE_HTTP_ADDR、开始干活
//   Stop：模块优雅关闭（幂等）
//   Health：宿主定期探活；不健康时宿主可重启该进程
type Module interface {
	Manifest() Manifest
	Start() error
	Stop() error
	Health() HealthStatus
}

// ModulePlugin 是 go-plugin 适配器：把 Module 接口暴露成 net/rpc 服务。
type ModulePlugin struct {
	Impl Module
}

var _ hplugin.Plugin = (*ModulePlugin)(nil)

// Server 插件进程侧：返回 net/rpc 服务端（承载真实实现）。
func (p *ModulePlugin) Server(*hplugin.MuxBroker) (interface{}, error) {
	return &moduleRPCServer{Impl: p.Impl}, nil
}

// Client 宿主侧：返回 net/rpc 客户端代理。
func (p *ModulePlugin) Client(_ *hplugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return &moduleRPCClient{client: c}, nil
}

// ServeModule 模块进程的入口：阻塞服务 Module 接口直到宿主断开。
//
// 用法（cmd/plugins/*/main.go）：
//
//	plugin.ServeModule(&plugin.ModulePlugin{Impl: impl})
func ServeModule(p *ModulePlugin) {
	hplugin.Serve(&hplugin.ServeConfig{
		HandshakeConfig: Handshake,
		Plugins:         map[string]hplugin.Plugin{ModulePluginName: p},
	})
}

// moduleRPCServer 模块进程侧：承载真实实现。
type moduleRPCServer struct {
	Impl Module
}

func (s *moduleRPCServer) Manifest(_ struct{}, reply *Manifest) error {
	*reply = s.Impl.Manifest()
	return nil
}

func (s *moduleRPCServer) Start(_ struct{}, reply *Void) error {
	return s.Impl.Start()
}

func (s *moduleRPCServer) Stop(_ struct{}, reply *Void) error {
	return s.Impl.Stop()
}

func (s *moduleRPCServer) Health(_ struct{}, reply *HealthStatus) error {
	*reply = s.Impl.Health()
	return nil
}

// moduleRPCClient 宿主侧：远程调用模块进程。
//
// 注意：net/rpc 的 gob 编码要求客户端实参类型与服务端形参类型**完全一致**。
// 服务端方法形参为 struct{}，这里必须传 struct{}{}（不能传 new(interface{})，
// 否则 gob 解码失败并导致连接被关闭——表现为 "connection is shut down"）。
type moduleRPCClient struct {
	client *rpc.Client
}

var _ Module = (*moduleRPCClient)(nil)

func (c *moduleRPCClient) Manifest() Manifest {
	var m Manifest
	if err := c.client.Call(rpcServiceName+".Manifest", struct{}{}, &m); err != nil {
		return Manifest{}
	}
	return m
}

func (c *moduleRPCClient) Start() error {
	return c.client.Call(rpcServiceName+".Start", struct{}{}, &Void{})
}

func (c *moduleRPCClient) Stop() error {
	return c.client.Call(rpcServiceName+".Stop", struct{}{}, &Void{})
}

func (c *moduleRPCClient) Health() HealthStatus {
	var h HealthStatus
	if err := c.client.Call(rpcServiceName+".Health", struct{}{}, &h); err != nil {
		return HealthStatus{Healthy: false, Message: err.Error()}
	}
	return h
}
