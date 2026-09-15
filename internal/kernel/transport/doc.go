// Package transport 是对外接待窗口（HTTP 请求 + WebSocket 实时推送）。
//
// 设计依据：
//   - v3 流程梯队 1.7："transport：网页请求入口、实时推送入口搭好（只搭架子）"
//   - 文件结构第 3.1 节："浏览器请求和实时推送都从这进出（HTTP/WebSocket）"
//   - v0.3 架构第 6.3 节："标准 net/http 或 chi，不引重量级框架"
//   - 实施方案 2.0 第 6.9 节：动态告警/处置走 WebSocket，按 capture_id+role 订阅
//
// 当前为"架子版"：
//   - HTTP 服务器基于标准库 net/http（Go 1.22+ ServeMux 已支持方法+路径参数）
//   - 内置中间件链：请求 ID → 访问日志 → panic 恢复
//   - REST 路由注册（方法 + 路径 + 处理器）
//   - WebSocket 端点注册（gorilla/websocket，实时推送的最小实现）
//   - 优雅关闭（Shutdown 带超时）
//
// 不在这里实现：
//   - 具体业务 API（auth/captures/packets/... 由各业务模块注册路由）
//   - 认证中间件（auth 模块实现后注入）
//   - WS 订阅鉴权（auth 模块实现后注入）
package transport
