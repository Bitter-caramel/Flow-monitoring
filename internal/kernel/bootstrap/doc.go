// Package bootstrap 是平台的总开机按钮。
//
// 设计依据：
//   - v3 流程梯队 1.9："bootstrap：开机时自动按登记本把模块依次启动；总开关，不写业务"
//   - 文件结构第 3.1 节："程序启动时读配置、查注册表、按顺序叫醒所有模块，全醒后宣布'准备好了'"
//   - v0.3 架构第 5 章启动链路设计
//
// 职责：
//   - 读配置（config.Load）
//   - 初始化日志（logging.NewFromConfigFile）
//   - 创建内核组件实例（registry/lifecycle/eventbus/transport/health）
//   - 注册内核模块到 registry（transport / health）
//   - 按拓扑序启动（lifecycle.StartAll）
//   - 注册 /healthz 路由
//   - 阻塞等待退出信号，收到后优雅关闭（逆序停模块 → 关闭事件总线）
//
// 不在这里实现业务模块的注册——业务模块在各自 init() 中向 registry.Default
// 注册自己（v3 梯队 2+ 会逐步加入）。
package bootstrap
