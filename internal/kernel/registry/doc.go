// Package registry 是插件登记本。
//
// 设计依据（参考 DSH / Cordis）：
//   - 每个功能模块都是一个 plugin.Plugin，在 init() 中自注册到 Default
//   - bootstrap 只读注册表，按拓扑序装配（Mount → Start）
//   - 插件只依赖服务名（plugin.Context.Get），不依赖具体实现
//
// 与 contract 包的区别：
//   - registry：管"插件本身"——插件身份、依赖关系、装配顺序
//   - contract：管"接口契约"——某个 API 的版本、能力、实现指针
//
// 可替换性：
//   - Register：同 ID 冲突报错（保护内置插件）
//   - Replace：强制覆盖（用户用同名插件替换内置实现）
package registry
