// Package importer 是流量分析的进货口。
//
// 设计依据：
//   - v3 流程梯队 2.16："importer：用户上传文件后收下、检查、切块、入库"
//   - 文件结构第 3.2 节："用户上传抓包文件，它收下、检查、切块、送解析、入库"
//   - 实施方案 2.0 第 7.1 节导入流程
//
// 职责编排（单条链路）：
//   文件字节 → pcapng.Parse（容器解析）→ decoder.Decode（协议解码）
//   → 转 storage.PacketRecord → packetstore.SaveCapture（文件 + 元数据 + 索引入库）
//
// 本包是解析核心（parse/*）与存储（storage/packetstore）之间的粘合层，
// 让 parse-cli 的解析能力变成可持久化、可查询的服务能力。
package importer
