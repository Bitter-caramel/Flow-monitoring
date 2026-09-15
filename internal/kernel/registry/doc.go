// Package registry 是模块登记本。
//
// 注意与 contract 包的区别（容易混淆）：
//   - contract 包：管"接口契约"——某个 API 的版本、能力、实现指针
//   - registry 包：管"模块本身"——模块元数据、依赖关系、启动函数
//
// 一个模块 X 在 init() 中可能同时做两件事：
//  1. 把自己注册到 registry.Default（声明 ID/依赖/启动函数）
//  2. 把它实现的契约注册到 contract.Default（如 contract.Default.Register(&Contract{ID:"foo.api", ...})）
//
// bootstrap 启动时按 registry.TopologicalSort() 的顺序调用每个模块的 StartFn。
//
// 设计依据 v3 流程梯队 1.4 + v0.3 文件结构第 3.1 节：
//   - 模块能登记，能看出谁依赖谁
//   - 能发现循环依赖（启动期拒绝启动）
//   - 启动时只读（运行期不允许新增模块，避免热加载失控）
package registry
