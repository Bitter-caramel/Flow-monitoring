package plugin

// Layer 插件层级。
type Layer int

const (
	LayerKernel     Layer = iota // L0 内核
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

// Manifest 插件元信息（"身份证"）。
//
// Provides 声明该插件向 Context 注册的服务名（其他插件依赖它时用这些名字 Get）。
// Depends 声明该插件依赖的其他插件 ID（装配时做拓扑排序与存在性校验）。
type Manifest struct {
	ID       string
	Name     string
	Version  string
	Layer    Layer
	Depends  []string // 依赖的插件 ID
	Provides []string // 提供的服务名（对应 Context.Provide）
}

// Plugin 统一插件接口。
//
// 生命周期（由装配器按序调用）：
//   Mount：注册服务到 Context（此时可 Get 依赖），只做声明不启动
//   Start：建立外部连接 / 启动 worker
//   Stop：关闭外部连接 / 停止 worker（应可幂等）
//
// 对应 Cordis 的 apply(ctx)：Mount 等价 apply，服务注册进 ctx，
// 返回的清理动作由 Stop 承担。
type Plugin interface {
	Manifest() Manifest
	Mount(ctx *Context) error
	Start(ctx *Context) error
	Stop(ctx *Context) error
}

// Base 空实现（供简单插件嵌入，避免重复写空方法）。
type Base struct{}

// Manifest 返回空 manifest（子类需覆盖）。
func (Base) Manifest() Manifest { return Manifest{} }

// Mount 默认空实现。
func (Base) Mount(*Context) error { return nil }

// Start 默认空实现。
func (Base) Start(*Context) error { return nil }

// Stop 默认空实现。
func (Base) Stop(*Context) error { return nil }
