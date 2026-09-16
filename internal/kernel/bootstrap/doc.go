// Package bootstrap 是平台的总开机按钮（L0 内核）。
//
// 设计依据：
//   - v3 流程梯队 1.9：bootstrap 开机时按登记本把模块依次启动，总开关不写业务
//   - 文件结构 §3.1：程序启动时读配置、查注册表、按顺序叫醒所有模块，全醒后 ready
//   - 架构 v0.3 P1：内核最小化——内核不 import 业务模块
//
// 与旧版的关键区别：
//   - 不再 import 业务模块、不再用 init() 自注册；模块清单来自 registry（内置+扩展文件）
//   - 模块以独立进程运行（pluginhost.Manager），内核只通过 pkg/plugin 契约通信
package bootstrap
