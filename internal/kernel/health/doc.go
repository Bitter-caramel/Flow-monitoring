// Package health 是平台的体检报告模块。
//
// 设计依据：
//   - v3 流程梯队 1.8："health：能报告'我还活着、哪个部件坏了'（依赖探针）"
//   - 文件结构第 3.1 节："定时报告'我还活着吗、哪个部件挂了'"
//   - v0.3 架构第 10 章："自身健康探针：situation-engine 上报处理时延与队列深度"
//   - 实施方案 2.0 第 6.10 节：`/healthz` 覆盖可观测性
//
// 健康状态有两个来源，本包负责聚合：
//  1. 模块生命周期状态（lifecycle.Coordinator.States()）：Created/Started/Error...
//  2. 模块自定义探针（registry.ModuleInfo.HealthFn）：返回 HealthStatus
//
// 本包不依赖 transport（避免循环依赖）：bootstrap 负责把 Handler() 注册到
// transport 的 /healthz 路由。
package health
