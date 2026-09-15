// Package contract 是模块间"签合同"的规矩。
//
// 设计依据 v3 流程梯队 1.3 + v0.3 架构第 7 章：
//   - 模块只依赖契约 API（不依赖具体实现）
//   - 契约语义化版本（SemVer）
//   - 契约测试矩阵（先立框架，等首批契约落地后补具体测试）
//   - SPI 依赖倒置（业务实现注册到契约注册表，调用方查表使用）
//   - 能力探针优雅降级（HasCapability 探针让旧客户端能跑新版本）
//   - 兼容层 adapter（未来跨大版本时引入）
//
// 本包只提供"契约元数据框架"：
//   - ContractID / Version / Contract 类型
//   - Registry：契约注册表（包级单例 + 注入版）
//   - 错误类型：ErrConflict / ErrNotFound / ErrCapabilityNotFound
//   - TestMatrix：契约测试矩阵入口（骨架，等首批契约落地补具体用例）
//
// 不在这里定义具体业务契约（如 SituationAPI、DisposalAPI、ParseService）——
// 它们由各业务模块在自己的包中定义，并通过 init() 注册到本包的 Registry。
package contract
