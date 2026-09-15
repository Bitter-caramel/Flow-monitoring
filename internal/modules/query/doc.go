// Package query 是查询窗口（前端唯一数据来源）。
//
// 设计依据：
//   - v3 流程梯队 2.17："query-api：查询接口做好：分页取包、取流、取协议树。
//     前端唯一数据来源"
//   - 实施方案 2.0 第 12.1 节 REST 资源
//
// 提供：
//   - Service：基于 storage.Storage 的查询逻辑（分页取包/取 capture 列表）
//   - Handler：HTTP 路由（由 bootstrap 注册到 transport）
//
// REST 接口（对应实施方案 2.0）：
//   - GET /api/v1/captures                    → capture 列表（分页）
//   - GET /api/v1/captures/{id}               → capture 详情
//   - GET /api/v1/captures/{id}/packets       → 包列表（分页）
//
// 本包只依赖 storage（不依赖 transport），Handler 返回 http.Handler，
// 由调用方（bootstrap 或 cmd）注册到 transport.Server。
package query
