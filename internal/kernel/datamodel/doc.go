// Package datamodel 是全项目的"数据字典"。
//
// 这里定义的所有对象（Packet / Capture / Flow / Subject 等）是跨模块共享的
// 统一类型，任何模块（解析器、存储、查询、态势、检测等）都通过这些类型
// 交换数据，禁止在业务代码里另起一套同名结构。
//
// 设计依据：
//   - v3 流程梯队 1.1（数据先于逻辑：数据结构最先定型，后期改代价最大）
//   - v0.3 架构第 9 章（双层对象模型：Flow 轻量 + Subject 有状态）
//   - 实施方案 2.0 第 5.2 节（核心数据对象表）
//   - PacketLens makePacket（index.html:990）字段集对照
//
// 字段命名遵循 PacketLens 原名（如 tf/plen/sid/sdir），便于后续协议解析器
// 重构时一一对照；展示用字段（如 Src/Dst 字符串）与运算用字段（如 SrcIPNum 整数）
// 同时保留，参考"IPv4 整数化 + 字段索引"性能优化思路。
package datamodel
