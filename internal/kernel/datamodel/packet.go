package datamodel

import "time"

// Packet 单个数据包的统一对象模型。
//
// 字段集对照 PacketLens makePacket (index.html:990)。
// 设计要点（参考 pcapng解包逻辑拆解.md §7.1）：
//   - 一次性固化字段（Go 的宽 struct 天然对应 V8 hidden class 优化）
//   - L7 解析结果按需分配为指针，nil = 未解析，避免无谓对象分配
//   - IPv4 同时保留字符串（展示）与整数（运算）双写，加速过滤/会话 key
//   - 时间戳用 time.Time（绝对）+ Rel float64（相对）双轨，避免浮点累积误差
//
// 该结构被解析层（decoder）写入、分析层（analyzer）读取并补充流字段、
// 存储层（packet-store）按偏移索引、查询层（query-api）按需物化。
type Packet struct {
	// === 帧元信息（parsePcapNG/parsePcap 阶段注入） ===
	No      int       // 包序号，从 1 开始
	Sec     int64     // 时间戳秒（绝对）
	Usec    int64     // 时间戳小数部分（单位依赖接口 tsresol，常见为微秒）
	Time    time.Time // 绝对时间（解析时按 tsresol/tsoff 换算）
	Rel     float64   // 相对首个包的秒数（用于排序、时序图）
	CapLen  int       // 实际抓包字节长度（caplen）
	OrigLen int       // 原始线路长度（origlen，可能 > CapLen，因 snaplen 截断）
	Iface   int       // 所属接口 ID（pcapng IDB 索引）
	Data    []byte    // 原始字节（解析用，subarray 零拷贝视图）
	DataOff int64     // 在 Capture.Raw 中的偏移（按需取字节用）
	NoTime  bool      // SPB 类无时间戳包
	Snapped bool      // snaplen 截断标记（CapLen < OrigLen）

	// === 展示层字段（decoder 阶段注入） ===
	Proto      string // 协议名（如 "HTTP"/"TCP"/"DNS"），原 proto
	Info       string // Wireshark 风格 INFO 列
	Src        string // 源地址（展示，IP 或 MAC）
	Dst        string // 目的地址
	SrcPort    uint16 // 源端口，sp
	DstPort    uint16 // 目的端口，dp
	IPProto    uint8  // IP 协议号（6=TCP,17=UDP,1=ICMP...），原 ist
	TCPFlags   uint16 // TCP 标志位压缩（SYN/ACK/FIN/RST/PSH...），tf
	PayloadLen int    // 载荷长度，plen
	PayloadOff int    // 载荷偏移，poff
	PathStr    string // 协议路径字符串（统计模式拼接，如 ",eth,ip4,tcp,http,"）

	// === 流归属（analyzer 阶段注入） ===
	StreamID   int       // 流 ID（sid，-1=未分配）
	StreamDir  uint8     // 流方向（0/1，sdir）
	Retransmit bool      // 重传标志，reTx
	TCPEvent    *TCPEvent // TCP 状态机事件（reTx 的扩展）

	// === 链路层 ===
	SrcMAC    string // 源 MAC，esrc
	DstMAC    string // 目的 MAC，edst
	EtherType uint16 // EtherType，etype

	// === 网络层 ===
	IPVersion uint8  // 4 或 6，ipv
	SrcIP     string // 源 IP（展示），isrc
	DstIP     string // 目的 IP（展示），idst
	SrcIPNum  uint32 // 源 IPv4 整数（用于 O(1) 过滤/会话 key），isrcN
	DstIPNum  uint32 // 目的 IPv4 整数，idstN
	TTL       uint8
	IPID      uint16 // IP 标识，ipid
	IPLen     int    // IP 总长，iplen
	DF        bool   // Don't Fragment
	MF        bool   // More Fragments
	FragOff   int    // Fragment Offset，fo（8 字节单位）
	Fragmented bool  // 是否分片（FragOff>0 或 MF）

	// === 异常标志 ===
	Malformed bool // 解码异常，mal
	CksumBad  bool // 校验和错误，ckbad

	// === L7 解析结果（按需分配，nil = 未解析） ===
	ICMP   *ICMP
	ARP    *ARP
	DHCP   *DHCP
	DNS    *DNS
	TLS    *TLS
	HTTP   *HTTP
	SNMP   *SNMP
	RADIUS *RADIUS
	SIP    *SIP
	SMB    *SMB
	MQTT   *MQTT
	SQL    *SQL
	Syslog *Syslog
	NBNS   *NBNS
	TFTP   *TFTP
	Telnet *Telnet
	QUIC   *QUIC
	ToPT   *ToPT
}

// TCPEvent 描述 TCP 流状态机相关事件，挂在 Packet 上供流分析使用。
// 对照 PacketLens engine.js 中 reTx/tcpEv/hsRtt 字段。
type TCPEvent struct {
	Kind string // 事件类型："syn"/"syn-ack"/"ack"/"rst"/"fin"/"zero-wnd"/"dup-ack"...
	Seq  uint32
	Ack  uint32
	RTT  time.Duration // 握手 RTT（仅 syn-ack 时有意义）
}

// NewPacket 创建零值 Packet，StreamID=-1 表示未分配。
// 等价于 PacketLens makePacket 的"固化字段模板"作用。
func NewPacket() *Packet {
	return &Packet{
		StreamID: -1,
		Proto:    "?",
	}
}
