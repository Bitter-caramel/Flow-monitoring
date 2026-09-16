package plugin

import (
	"context"
	"net"
	"net/http"
	"os"
	"time"
)

// EnvHostBridge 模块进程读取宿主桥接地址的环境变量名（宿主 Launch 时注入）。
const EnvHostBridge = "FLOW_HOST_BRIDGE"

// Runtime 模块进程运行时脚手架。
//
// 封装所有模块进程的公共样板：回连宿主、读配置快照、按 Manifest.HTTPBase
// 起 HTTP 服务并上报网关。业务模块只需：
//
//	rt := &plugin.Runtime{
//	    Spec:     plugin.Manifest{ID: "modules.xxx", ...},
//	    Handler:  mux,                 // 有 HTTP 时提供；无则 nil
//	    OnStart:  func(host plugin.Host, cfg plugin.ConfigSnapshot) error { ... },
//	    OnStop:   func() error { ... },
//	}
//	plugin.ServeModule(&plugin.ModulePlugin{Impl: rt})
//
// 对应 DSH/Cordis 的"插件 apply(ctx) 返回可逆 effect"：Runtime 是标准实现，
// 业务差异收敛到 OnStart/OnStop 两个钩子。
type Runtime struct {
	Spec    Manifest // 模块身份（ID/层/依赖/HTTPBase）
	// MakeHandler 在 Start 回连宿主后调用，用宿主构造 HTTP handler（无 HTTP 时留 nil）。
	MakeHandler func(host Host) (http.Handler, error)
	OnStart     func(host Host, cfg ConfigSnapshot) error
	OnStop      func() error

	host      Host
	cfg       ConfigSnapshot
	ln        net.Listener
	srv       *http.Server
	injected  map[string]ServiceRef // 已解析的注入服务
	provided  []string              // 本模块注册的服务名（Stop 时回滚）
}

var _ Module = (*Runtime)(nil)

// Manifest 返回模块身份（实现 Module 接口）。
func (r *Runtime) Manifest() Manifest { return r.Spec }

// Host 返回宿主桥接客户端（Start 后可用）。
func (r *Runtime) Host() Host { return r.host }

// Config 返回配置快照（Start 后可用）。
func (r *Runtime) Config() ConfigSnapshot { return r.cfg }

// Injected 取注入的服务引用（对应 DSH 的 inject；Start 后可用）。
func (r *Runtime) Injected(name string) (ServiceRef, bool) {
	ref, ok := r.injected[name]
	return ref, ok
}

// Start 回连宿主、读配置、起 HTTP（若声明）、注册/解析服务、执行业务钩子。
//
// 服务装配（DSH 式）：
//  1. 先按 Spec.Provides 把本模块的服务注册到宿主服务表；
//  2. 再按 Spec.Injects 解析所需服务（宿主保证提供者已先启动）；
//  3. 最后执行 OnStart —— 业务代码此时可直接用 r.Injected(name)。
func (r *Runtime) Start() error {
	host, err := DialHostFromEnv()
	if err != nil {
		return err
	}
	r.host = host
	r.cfg = host.Config()
	r.injected = make(map[string]ServiceRef)

	// 1. HTTP 服务（若声明）
	endpoint := r.Spec.ID // 无 HTTP 的服务用模块 ID 作总线命名空间
	kind := ServiceKindBus
	if r.Spec.HTTPBase != "" && r.MakeHandler != nil {
		h, err := r.MakeHandler(host)
		if err != nil {
			return err
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		r.ln = ln
		r.srv = &http.Server{Handler: h}
		go func() { _ = r.srv.Serve(ln) }()
		if err := host.RegisterHTTP(r.Spec.HTTPBase, ln.Addr().String(), r.Spec.ID); err != nil {
			return err
		}
		endpoint = ln.Addr().String()
		kind = ServiceKindHTTP
	}

	// 2. 注册本模块提供的服务（可逆副作用）
	for _, name := range r.Spec.Provides {
		ref := ServiceRef{Name: name, Kind: kind, Endpoint: endpoint, ModuleID: r.Spec.ID}
		if err := host.RegisterService(ref); err != nil {
			return err
		}
		r.provided = append(r.provided, name)
	}

	// 3. 解析注入的服务
	for _, name := range r.Spec.Injects {
		if ref, ok := host.LookupService(name); ok {
			r.injected[name] = ref
		} else {
			host.Log("warn", "module "+r.Spec.ID+" injects missing service: "+name)
		}
	}

	// 4. 业务钩子
	if r.OnStart != nil {
		return r.OnStart(host, r.cfg)
	}
	return nil
}

// Stop 回滚服务注册、执行业务停止钩子并关闭 HTTP 服务（幂等）。
func (r *Runtime) Stop() error {
	if r.host != nil {
		for _, name := range r.provided {
			_ = r.host.UnregisterService(name)
		}
	}
	r.provided = nil
	if r.OnStop != nil {
		_ = r.OnStop()
	}
	if r.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = r.srv.Shutdown(ctx)
	}
	return nil
}

// Health 返回运行态健康（进程存活即健康）。
func (r *Runtime) Health() HealthStatus { return HealthStatus{Healthy: true} }

// DialHostFromEnv 从环境变量回连宿主桥接服务。
func DialHostFromEnv() (Host, error) {
	addr := os.Getenv(EnvHostBridge)
	if addr == "" {
		return nil, ErrMissingDependency
	}
	return DialHost(addr)
}
