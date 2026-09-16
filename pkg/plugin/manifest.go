// Package plugin 是流量分析平台的插件 SDK（公共契约层）。
//
// 定位对应文件结构文档 §7 的 pkg/：开放给外部写插件时引用的公共代码。
// 宿主（kernel）与每个模块进程（cmd/plugins/*）都 import 本包，共享同一套
// 契约类型，从而保证跨进程通信的类型安全（gob 序列化要求两端类型一致）。
//
// 架构分工：
//   - 本包只定义"契约"（Manifest/Module/Host/数据记录），不含任何实现；
//   - Module 是模块进程对宿主暴露的生命周期接口（宿主通过 go-plugin 调用）；
//   - Host 是宿主对模块进程暴露的服务接口（模块通过 net/rpc 回连调用）；
//   - 模块与模块之间不直接通信，只通过宿主的 eventbus（Publish/Poll）解耦。
package plugin

// Layer 模块所属层级（L0~L3），对应架构设计 v0.3 第 3 章分层全表。
type Layer int

const (
	LayerKernel     Layer = iota // L0 内核（宿主进程内，不作为插件进程）
	LayerFoundation              // L1 基础功能
	LayerFeature                 // L2 具体功能
	LayerExtension               // L3 用户扩展
)

// String 层级名。
func (l Layer) String() string {
	switch l {
	case LayerKernel:
		return "L0"
	case LayerFoundation:
		return "L1"
	case LayerFeature:
		return "L2"
	case LayerExtension:
		return "L3"
	}
	return "L?"
}

// Manifest 模块元信息（"身份证"）。
//
// 对应文件结构文档 §6 的 registry/ 声明文件在运行期的等价形态：
// bootstrap 据此做拓扑排序、依赖校验、服务装配与网关路由注册。
//
//   - Depends：显式依赖的模块 ID（装配顺序）
//   - Provides：本模块对外注册的**服务名**（DSH 的 ctx.provide）
//   - Injects：本模块需要的**服务名**（DSH 的 inject）
//   - HTTPBase：模块对外提供的 HTTP 路由前缀（如 "/api/v1/captures"）
//
// 服务装配规则（DSH 式声明式注入）：
//   - 宿主从全部模块的 Provides 建"服务名 → 提供者模块"映射；
//   - Injects 里的服务名会被展开成对提供者模块的隐含依赖，参与拓扑排序，
//     保证"提供者先启动、消费者后启动"；消费者在 Start 时即可解析到服务。
type Manifest struct {
	ID       string
	Name     string
	Version  string
	Layer    Layer
	Depends  []string // 依赖的模块 ID
	Provides []string // 提供的服务名
	Injects  []string // 注入（需要）的服务名
	HTTPBase string   // HTTP 路由前缀；空 = 不提供 HTTP
}

// HealthStatus 模块健康状态（供宿主健康检查聚合）。
type HealthStatus struct {
	Healthy bool
	Message string
}

// 服务种类（ServiceRef.Kind）。
const (
	ServiceKindHTTP = "http" // 模块自己的 HTTP 服务，Endpoint = "127.0.0.1:port"
	ServiceKindBus  = "bus"  // 事件总线服务，Endpoint = 主题前缀
)

// ServiceRef 服务引用：模块间服务注册/注入的载体。
//
// 对应 DSH 的 Service Provider / Consumer 模型：
// 提供者注册本结构，消费者按 Name 查到它并据此调用（HTTP 服务直连，
// 数据服务走事件总线）。
type ServiceRef struct {
	Name     string `json:"name"`      // 服务名，如 "query.api"
	Kind     string `json:"kind"`      // "http" | "bus"
	Endpoint string `json:"endpoint"`  // http: 监听地址；bus: 主题前缀
	ModuleID string `json:"module_id"` // 提供者模块 ID
}
