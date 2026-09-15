// Package decoder 是协议解码层（L2/L3/L4 + 常见 L7）。
//
// 设计依据：
//   - pcapng解包逻辑拆解.md §4（数据包解码流程 L2/L3/L4/L7 层层解析）
//   - PacketLens 源码 PA.dec（engine.js:1371-2440，对应 index.html:1641-2710）
//
// 当前实现范围（P0 最小可用，对应拆解文档 §8.3）：
//   - L2：Ethernet II（含 802.1Q VLAN 递归展开）、ARP
//   - L3：IPv4（分片标记）、IPv6（扩展头基本处理）
//   - L4：TCP、UDP、ICMP
//   - L7：暂由后续 internal/modules/parse/decoder/l7 补充
//
// 解码结果写入 *datamodel.Packet 的字段（对应 PacketLens makePacket 字段集）：
//   - Proto/Info/Src/Dst：协议名 / INFO 摘要 / 源目的地址
//   - SrcMAC/DstMAC/EtherType：链路层
//   - SrcIP/DstIP/SrcIPNum/DstIPNum/TTL/IPProto/IPLen/IPID/DF/MF/FragOff/Fragmented：网络层
//   - SrcPort/DstPort/TCPFlags/PayloadLen/PayloadOff：传输层
//   - PathStr：协议路径字符串（统计模式，如 ",eth,ip4,tcp,"）
//
// 字节序说明：网络协议（Ethernet/IP/TCP/UDP）一律使用网络字节序（大端），
// 与 pcapng 容器的 section 字节序无关；pcapng 的字节序仅影响容器层字段。
package decoder
