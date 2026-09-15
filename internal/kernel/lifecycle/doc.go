// Package lifecycle 是模块开机/关机管理。
//
// 设计依据 v3 流程梯队 1.5："lifecycle：模块的'开机/关机'流程状态可跑；统一启停"。
//
// 职责边界：
//   - 单模块的状态机（Created → Initializing → Initialized → Starting →
//     Started → Stopping → Stopped / Error）
//   - 批量启停协调（Coordinator）：按 registry.TopologicalSort() 顺序启动，
//     逆序关闭；启动失败时回滚已启动模块
//
// 不在这里实现：
//   - 模块注册（registry 干的活）
//   - 启动顺序决策（registry.TopologicalSort 干的活）
//   - 健康上报（health 模块干的活，但可通过 Coordinator.States() 拿状态源）
package lifecycle
