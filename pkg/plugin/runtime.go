package plugin

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// EnvHostBridge 模块进程读取宿主桥接地址的环境变量名（宿主 Launch 时注入）。
const EnvHostBridge = "FLOW_HOST_BRIDGE"

// StatusTopic 是模块向宿主自报运行状态的事件主题（模块 → 宿主方向）。
//
// 载荷是一段 JSON（见 StatusReport）；宿主侧由 internal/kernel/modulestatus 订阅。
// ★ 刻意不新增 RPC 方法：Host 契约（模块→宿主）已提供 Publish，方向无需反转。
const StatusTopic = "module.status"

// DefaultStatusInterval 是模块状态上报的默认周期（避免刷屏事件总线）。
const DefaultStatusInterval = 5 * time.Second

// StatusReport 是 module.status 主题的事件载荷。
//
// 键值全部是具体类型（字符串 map），保证经 net/rpc/gob 或 JSON 都能稳定编码。
type StatusReport struct {
	ModuleID string            `json:"module_id"`
	Healthy  bool              `json:"healthy"`
	Message  string            `json:"message"`
	Metrics  map[string]string `json:"metrics"`
	At       time.Time         `json:"at"`
}

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
	Spec Manifest // 模块身份（ID/层/依赖/HTTPBase）
	// MakeHandler 在 Start 回连宿主后调用，用宿主构造 HTTP handler（无 HTTP 时留 nil）。
	MakeHandler func(host Host) (http.Handler, error)
	OnStart     func(host Host, cfg ConfigSnapshot) error
	OnStop      func() error
	// OnHealth 可选：模块自定义健康检查。为 nil 时 Health 恒返回 healthy，
	// 保持既有模块零改动、向后兼容。
	OnHealth func() HealthStatus
	// StatusInterval 是状态上报周期；<=0 时使用 DefaultStatusInterval（5s）。
	// ★ 导出以便测试注入短周期（如 20ms），生产环境保持默认。
	StatusInterval time.Duration

	host     Host
	cfg      ConfigSnapshot
	ln       net.Listener
	srv      *http.Server
	injected map[string]ServiceRef // 已解析的注入服务
	provided []string              // 本模块注册的服务名（Stop 时回滚）

	// 状态上报 goroutine 的启停控制（Stop 时必须取消并等待退出）。
	statusMu     sync.Mutex
	statusCancel context.CancelFunc
	statusWG     sync.WaitGroup
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
		if err := r.OnStart(host, r.cfg); err != nil {
			return err
		}
	}

	// 5. 状态上报：Start 成功后起 goroutine 定期 Publish("module.status", ...)。
	r.startStatusReporter()
	return nil
}

// Stop 回滚服务注册、执行业务停止钩子并关闭 HTTP 服务（幂等）。
func (r *Runtime) Stop() error {
	// ★ 先停状态上报并等待退出：否则取消后仍有 goroutine 在写宿主（可能已关闭）。
	r.stopStatusReporter()
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

// Health 返回运行态健康。
//
// OnHealth 为 nil 时保持旧行为（进程存活即健康），现有模块零影响；
// 非 nil 时把真实状态交给模块自己判断。
func (r *Runtime) Health() HealthStatus {
	if r.OnHealth != nil {
		return r.OnHealth()
	}
	return HealthStatus{Healthy: true}
}

// startStatusReporter 启动状态上报 goroutine（幂等：已在运行则 no-op）。
//
// 必须在 Start 成功后调用（host 已就绪）；Stop 会取消并等待退出。
func (r *Runtime) startStatusReporter() {
	if r.host == nil {
		return
	}
	r.statusMu.Lock()
	if r.statusCancel != nil { // 已在运行
		r.statusMu.Unlock()
		return
	}
	interval := r.StatusInterval
	if interval <= 0 {
		interval = DefaultStatusInterval
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.statusCancel = cancel
	r.statusWG.Add(1)
	r.statusMu.Unlock()

	go r.reportStatusLoop(ctx, interval)
}

// reportStatusLoop 立即上报一次，随后按 interval 周期上报。
func (r *Runtime) reportStatusLoop(ctx context.Context, interval time.Duration) {
	defer r.statusWG.Done()
	r.publishStatus()

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.publishStatus()
		}
	}
}

// publishStatus 取一次 Health() 并把结果发布到 module.status。
//
// ★ 发布失败只记日志，绝不影响模块运行。
func (r *Runtime) publishStatus() {
	if r.host == nil {
		return
	}
	st := r.Health()
	metrics := st.Metrics
	if metrics == nil {
		metrics = map[string]string{}
	}
	payload, err := json.Marshal(StatusReport{
		ModuleID: r.Spec.ID,
		Healthy:  st.Healthy,
		Message:  st.Message,
		Metrics:  metrics,
		At:       time.Now(),
	})
	if err != nil {
		r.host.Log("warn", "module "+r.Spec.ID+" 状态序列化失败: "+err.Error())
		return
	}
	if err := r.host.Publish(StatusTopic, payload); err != nil {
		r.host.Log("warn", "module "+r.Spec.ID+" 状态上报失败: "+err.Error())
	}
}

// stopStatusReporter 取消状态上报并等待 goroutine 退出（幂等）。
func (r *Runtime) stopStatusReporter() {
	r.statusMu.Lock()
	cancel := r.statusCancel
	r.statusCancel = nil
	r.statusMu.Unlock()
	if cancel != nil {
		cancel()
	}
	r.statusWG.Wait()
}

// DialHostFromEnv 从环境变量回连宿主桥接服务。
func DialHostFromEnv() (Host, error) {
	addr := os.Getenv(EnvHostBridge)
	if addr == "" {
		return nil, ErrMissingDependency
	}
	return DialHost(addr)
}
