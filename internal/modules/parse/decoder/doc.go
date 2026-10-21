// Package decoder 是协议解码层（L2/L3/L4 + 常见 L7）。
//
// 实现方式（见 docs/未完成/定制化与检测规划.md §2「自研 vs 复用红线」）：
//   - L2/L3/L4 解码**复用 gopacket**（github.com/gopacket/gopacket，
//     社区维护的 fork；原 google/gopacket 已停更）。
//     解码是"苦力活"，且不同解码器的解码结果不一致会污染下游的
//     流聚合与检测，故统一采用社区标准实现。
//   - 热路径用 DecodingLayerParser（预分配层对象 + sync.Pool 复用，零分配）。
//   - L7 仍由本包内的 l7 子包负责（它只依赖 Packet.Data 与 PayloadOff/PayloadLen）。
//
// 解码结果写入 *datamodel.Packet 的字段（对应 PacketLens makePacket 字段集）：
//   - Proto/Info/Src/Dst：协议名 / INFO 摘要 / 源目的地址
//   - SrcMAC/DstMAC/EtherType：链路层
//   - SrcIP/DstIP/SrcIPNum/DstIPNum/TTL/IPProto/IPLen/IPID/DF/MF/FragOff/Fragmented：网络层
//   - SrcPort/DstPort/TCPFlags/PayloadLen/PayloadOff：传输层
//   - PathStr：协议路径字符串（统计模式，如 ",eth,ip4,tcp,"）
//
// 支持的链路类型：Ethernet(1/279)、NULL loopback(0)、裸 IP(12/14/101/228/229)。
//
// 字节序说明：网络协议（Ethernet/IP/TCP/UDP）一律使用网络字节序（大端），
// 与 pcapng 容器的 section 字节序无关；pcapng 的字节序仅影响容器层字段。
package decoder
