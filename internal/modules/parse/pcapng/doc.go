// Package pcapng 是 pcapng 抓包文件的容器解析器。
//
// 设计依据：
//   - pcapng解包逻辑拆解.md §3（parsePcapNG 逐步拆解）
//   - PacketLens 源码 parsePcapNG（index.html:1088）
//   - pcapng 规范（https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html）
//
// 当前实现范围（P0 最小可用，对应拆解文档 §8.3 迁移优先级）：
//   - SHB（Section Header Block）：字节序锚点 + 版本 + 元数据选项
//   - IDB（Interface Description Block）：链路类型 + 抓包长度 + 时间精度/偏移选项
//   - EPB（Enhanced Packet Block）：接口 ID + 64 位时间戳 + 抓包数据 + 包级选项
//   - 选项迭代器（4 字节对齐）
//   - 多 section 字节序中途切换
//
// 未实现（后续迭代）：
//   - SPB / obsolete Packet Block / NRB / ISB / DSB（P1）
//   - gzip 解压（P1）
//
// 与 datamodel 的关系：Parse 产出 *datamodel.Capture，其中每个 Packet.Data 通过
// 切片零拷贝引用 Capture.Raw 的字节区间（对应 PacketLens cap.raw 设计）。
package pcapng
