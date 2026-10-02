package datamodel

import "time"

// Interface pcapng IDB 描述的单一网络接口。
//
// 字段对应 PacketLens parsePcapNG 中 ifaces[] 的项（index.html:890-914）。
// tsresol 与 tsoff 是时间戳换算的关键：
//   - tsresol=6 → tsscale=1e6（微秒）；tsresol=9 → tsscale=1e9（纳秒）
//   - tsoff 是相对 1970-01-01 的偏移秒数（uint64，可能很大，注意无符号读）
type Interface struct {
	ID       int     // 在 ifaces 数组中的下标
	LinkType int     // LINKTYPE_*（1=Ethernet, 113=Linux SLL, 108=Loopback...）
	SnapLen  int     // 抓包长度上限
	Name     string  // 选项 2：if_name
	Desc     string  // 选项 3：if_description
	IPv4     string  // 选项 4：if_ipv4addr（含掩码，仅取地址部分）
	MAC      string  // 选项 6：if_macaddr
	Speed    uint64  // 选项 8：if_speed（bps）
	TSResol  *uint8  // 选项 9：if_tsresol；nil=默认 6（微秒）
	TSOffset int64   // 选项 14：if_tsoffset（秒，相对 1970-01-01）
	Filter   string  // 选项 11：if_filter
	OS       string  // 选项 12：if_os
	Hardware string  // 选项 15：if_hardware
	TSScale  float64 // 由 TSResol 计算后的缩放因子（1e6/1e9/2^n）
}

// TSScale 默认值：1e6 = 微秒精度。
// 对应 PacketLens tsScale() (index.html:985)：
//
//	if tsresol == null: 1e6
//	if tsresol & 0x80: 2^(tsresol & 0x7f)  // 二进制分辨率
//	else:               10^tsresol          // 十进制：0=秒,3=毫秒,6=微秒,9=纳秒
const DefaultTSScale = 1e6

// Capture 一个抓包文件容器。
//
// 对应 PacketLens parsePcapNG/parsePcap 返回值（index.html:1013+），
// 是解析器产出、存储层入口、查询层数据源的核心对象。
//
// 字段 Raw 是原始字节切片，所有 Packet.Data 都通过 DataOff+CapLen 在 Raw 中
// 零拷贝 subarray 引用——对应 PacketLens 中 cap.raw 的设计。
type Capture struct {
	Format   string            // "pcapng"/"pcap"/"pcap-mod"/"snoop"/"mitm"...
	Endian   string            // "little"/"big"
	Version  string            // 如 "1.0"
	SnapLen  int               // 全局 snaplen（pcap 来自文件头，pcapng 取首个 IDB）
	LinkType int               // 全局链路类型（同上）
	Ifaces   []Interface       // 接口列表（pcapng 单接口时仅 1 项）
	Packets  []*Packet         // 解析后的包列表（大文件时可为空，仅靠 Raw+索引）
	Raw      []byte            // 原始文件字节（gzip 解压后）
	GZipped  bool              // 是否经过 gzip 解压
	Kind     string            // sniff 后的格式标识
	Meta     CaptureMeta       // SHB 选项区元数据
	Warns    []string          // 非致命告警列表（截断/对齐/坏块...）
	NRB      map[uint32]string // NRB 名称解析：IP → 主机名
	DSB      int               // 解密密钥块计数
	Secrets  []TLSSecret       // DSB 内嵌的 TLS Keylog（每段一行）
	Comments []string          // EPB 选项 1：包级注释
	Stats    []InterfaceStat   // ISB 接口统计
	Sections int               // SHB 数量（多 section 文件）
}

// CaptureMeta 抓包文件来源元信息（SHB 选项 1-4）。
type CaptureMeta struct {
	Hardware string // opt 1: hardware
	OS       string // opt 2: os
	App      string // opt 3: user application（如"Dumpcap 4.0.4"）
	Comment  string // opt 4: user comment
}

// TLSSecret TLS Keylog 单条记录（DSB 内嵌或外部 keys.log）。
//
// 格式参考 NSS Key Log Format（SSLKEYLOGFILE）：
//
//	LABEL <space> CLIENT_RANDOM <hex> <hex>
//	LABEL <space> <id> <hex>
//
// Kind 常见值：CLIENT_RANDOM / CLIENT_EARLY_TRAFFIC_SECRET /
// CLIENT_HANDSHAKE_TRAFFIC_SECRET / SERVER_HANDSHAKE_TRAFFIC_SECRET /
// EXPORTER_SECRET / etc.
type TLSSecret struct {
	Kind string
	Data string // 原始行（包含 ID 与密钥 hex）
}

// InterfaceStat 接口统计（ISB 块）。
type InterfaceStat struct {
	IfaceID      int
	StartTS      time.Time
	EndTS        time.Time
	Received     uint64
	Dropped      uint64 // if_drops
	FilterAccept uint64
	OSDropped    uint64
	Delivered    uint64
}

// CaptureSummary 是 Capture 的轻量视图，用于列表展示。
// 大文件不入库时仅持久化此类摘要 + 原始 pcap 引用。
type CaptureSummary struct {
	ID          string // 数据库主键（UUID/雪花）
	Name        string // 用户可见名称
	Format      string
	LinkType    int
	PacketCount int
	ByteSize    int64 // 原始文件字节数
	SHA256      string
	FirstSeen   time.Time
	LastSeen    time.Time
	ImportedAt  time.Time
	SavePolicy  string // "full"/"threat-only"/"none"
}
