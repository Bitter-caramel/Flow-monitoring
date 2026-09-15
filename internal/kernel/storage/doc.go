// Package storage 是存储的接口标准（storage-core）。
//
// 设计依据：
//   - v3 流程梯队 2.10："storage-core：存储的统一接口定义完成（只定义不实现）"
//   - 文件结构第 3.1 节："storage：存储接口标准。规定'数据怎么存怎么取'，
//     但具体存哪由 modules 里的 store 实现"
//   - 实施方案 2.0 第 12.2 节：PostgreSQL 核心表（captures/packets/...）
//
// 本包只定义接口 + 存储专用类型 + 错误哨兵，不包含任何具体数据库实现。
// 具体实现由 internal/modules/store 提供（PostgreSQL db-adapter 等）。
//
// 设计原则（实施方案 2.0 第 4.4 节"storage 模块关键边界"）：
//   - 业务层不直接拼 SQL，只通过本包的接口存取
//   - 原始包字节不进数据库（只存元数据 + 文件引用），对应"百万级静态导入
//     不强制入库"
//   - 接口抽象允许后续从 PostgreSQL 迁移到 ClickHouse 等而不改业务层
package storage
