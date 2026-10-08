package datamodel

import "time"

// 本文件汇总各 L7 协议解析结果结构。
//
// 当前为"骨架版"：每个类型先放最常用字段，便于 datamodel 编译通过与跨模块引用。
// 协议解析器（internal/decoder/l7/*）实现时按需扩充字段；
// 任何扩充都建议同步更新本文件注释，方便团队对照。
//
// 字段命名尽量贴近 Wireshark 显示字段名（如 dns.qry.name），
// 便于熟悉 Wireshark 的用户上手；中文注释说明用途。

// ICMP 网络层控制消息。
type ICMP struct {
	Type         uint8  // 类型（8=Echo Request, 0=Echo Reply, 3=Dest Unreachable...）
	Code         uint8  // 代码
	Checksum     uint16 // 校验和
	ID           uint16 // Echo ID（请求/响应配对用）
	Seq          uint16 // Echo 序号
	DestUnreach  bool   // 是否"目标不可达"
	TimeExceeded bool   // 是否"超时"（TTL 用尽）
}

// ARP 地址解析协议。
type ARP struct {
	Opcode       uint16 // 1=请求, 2=响应
	SenderIP     string
	SenderMAC    string
	TargetIP     string
	TargetMAC    string
	IsGratuitous bool // 免费 ARP
}

// DHCP 动态主机配置。
type DHCP struct {
	Op        uint8  // 1=请求, 2=响应
	XID       uint32 // 事务 ID（请求/响应配对）
	CIADDR    string // 客户端 IP
	YIADDR    string // 你的 IP（分配的）
	SIADDR    string // 服务器 IP
	HostName  string // option 12
	LeaseTime uint32 // option 51（秒）
	MsgType   string // option 53: discover/offer/request/ack/nak
}

// DNS 域名解析。
type DNS struct {
	ID           uint16 // 事务 ID
	QR           bool   // false=查询, true=响应
	OpCode       uint8  // 0=标准查询, 4=反向, 5=动态更新
	RCode        uint8  // 0=NOERROR, 3=NXDOMAIN...
	Questions    []DNSQuestion
	Answers      []DNSResource
	Authorities  []DNSResource
	Additionals  []DNSResource
	ResponseTime time.Duration // 响应耗时（响应包配对请求时填）
}

// DNSQuestion DNS 问题段。
type DNSQuestion struct {
	Name  string // 查询域名
	Type  uint16 // A=1, NS=2, CNAME=5, SOA=6, PTR=12, MX=15, AAAA=28, TXT=16...
	Class uint16 // IN=1
}

// DNSResource DNS 资源记录（答案/权威/附加段共用）。
type DNSResource struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  string // 解析后的人类可读形式（A 记录=IP，MX=主机+优先级...）
}

// TLS 传输层安全协议。
type TLS struct {
	RecordType    uint8  // 22=Handshake, 23=ApplicationData, 24=ChangeCipherSpec
	RecordVersion uint16 // 0x0301=TLS1.0, 0x0302=TLS1.1, 0x0303=TLS1.2
	HandshakeType uint8  // 1=ClientHello, 2=ServerHello, 11=Certificate, 16=ClientKeyExchange...
	SNI           string // Server Name Indication（客户端意向主机名）
	Version       uint16 // 协商版本
	CipherSuite   uint16 // 协商密码套件
	ALPN          string // 应用层协议协商（h2/http1.1）
	JA3           string // 客户端指纹
	JA4           string // 客户端指纹（新版）
	ServerName    string // 证书 CN
	CertChain     []TLSCertificate
}

// TLSCertificate TLS 证书。
type TLSCertificate struct {
	CN         string // Common Name
	Issuer     string // 颁发者 CN
	NotBefore  string
	NotAfter   string
	SelfSigned bool
	WeakSig    bool // MD5/SHA1
}

// HTTP 超文本传输。
type HTTP struct {
	IsRequest     bool
	Method        string // GET/POST/PUT/DELETE...
	URI           string
	StatusCode    int
	StatusText    string
	Host          string
	UserAgent     string
	ContentType   string
	ContentLength int64
	RequestTime   time.Time
	ResponseTime  time.Time
	Duration      time.Duration
	Decrypted     bool // 来自 TLS 解密还原（区分链路明文）

	// 以下数字均为"相对本包应用层载荷"的偏移/长度，仅记录数字、不保存 []byte，
	// 避免 L7 结构绑定抓包缓冲区的生命周期（实时抓包缓冲区会被复用，切片会读到脏数据）。
	// 检测引擎将来用 pkt.Data 按这些偏移现切出 http_header / http_client_body 缓冲区。
	HeaderLen int // HTTP 头段长度（含结尾的 \r\n\r\n）；0 = 未知
	BodyOff   int // 正文相对载荷的起始偏移；0 = 未知（头长 > 0 时正文也可能为空）
	URIOff    int // 请求行中 URI 相对载荷的起始偏移；0 = 未知（响应没有 URI）
	URILen    int // URI 长度
	MethodOff int // 请求行中 Method 相对载荷的起始偏移；0 = 未知（响应没有 Method）
	MethodLen int // Method 长度
}

// SNMP 简单网络管理。
type SNMP struct {
	Version   uint8 // 1=SNMPv1, 2=SNMPv2c, 3=SNMPv3
	Community string
	PDUType   uint8
}

// RADIUS 远程认证拨入用户服务。
type RADIUS struct {
	Code       uint8 // 1=Access-Request, 2=Access-Accept, 3=Access-Reject...
	Identifier uint8
	UserName   string
}

// SIP 会话发起协议。
type SIP struct {
	Method     string // INVITE/REGISTER/BYE...
	URI        string
	StatusCode int
	StatusText string
	From       string
	To         string
	CallID     string
}

// SMB 服务消息块。
type SMB struct {
	ProtocolID uint32 // 0xff SMB1, 0xfe SMB2
	Command    uint16
	Status     uint32
	SessionID  uint64
	TreeID     uint32
}

// MQTT 消息队列遥测传输。
type MQTT struct {
	MsgType  uint8 // 1=CONNECT, 3=PUBLISH, 4=PUBACK, 8=SUBSCRIBE...
	ClientID string
	Topic    string
	QoS      uint8
}

// SQL 数据库协议（MySQL/MSSQL/PostgreSQL 检测后填）。
type SQL struct {
	Dialect string // mysql/mssql/postgres
	Command string
}

// Syslog 系统日志。
type Syslog struct {
	Facility uint8
	Severity uint8
	Message  string
}

// NBNS NetBIOS 名称服务。
type NBNS struct {
	TID        uint16
	IsResponse bool
	Question   string
}

// TFTP 简单文件传输。
type TFTP struct {
	Op       uint16 // 1=RRQ, 2=WRQ, 3=DATA, 4=ACK, 5=ERROR
	FileName string
	Mode     string
}

// Telnet 远程终端。
type Telnet struct {
	Command uint8 // 0xff=IAC 后跟命令
	Data    string
}

// QUIC 快速 UDP 互联网连接。
type QUIC struct {
	Version   uint32
	DCID      string // 目的连接 ID
	SCID      string // 源连接 ID
	IsInitial bool
}

// ToPT Trusted Overlay Protocol Transport（保留位，等需要时再补全）。
type ToPT struct {
	Reserved bool
}
