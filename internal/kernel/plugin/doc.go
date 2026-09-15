// Package plugin 是统一插件契约（内核）。
//
// 设计依据（参考 DSH / Cordis 的 everything-is-a-plugin 理念）：
//   - 每个功能模块都是一个插件：实现 Plugin 接口，在 init() 中自注册到注册表
//   - Context 是依赖注入容器：插件在 Mount 阶段注册自己提供的服务，
//     并从 Context 获取它依赖的服务
//   - bootstrap 只读注册表，按拓扑序装配（Mount → Start），不直接 import 创建模块
//
// 三角色（对应 DSH 的 Service Definition / Provider / Consumer）：
//   - Manifest：能力定义（插件是谁、依赖谁、提供什么服务）
//   - Plugin.Mount/Start/Stop：能力提供（具体实现）
//   - Context.Get：能力消费（其他插件通过服务名获取依赖）
//
// 可替换性：两个插件注册相同 ID 时，后注册者替换先注册者；
// 消费方只依赖服务名（Context.Get），不依赖具体实现，换 Provider 不改 Consumer。
package plugin
