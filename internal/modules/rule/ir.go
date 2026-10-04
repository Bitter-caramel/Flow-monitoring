// Package rule 是规则翻译器：把 Suricata 规则文本翻译成内部可执行格式。
//
// 本文件定义**中间表示（IR）**——与 Suricata 语法解耦的内部规则模型，
// 是翻译器三层（解析 → 规范化 → 编译）之间的"合同"，也是全模块最稳定的接口。
//
// IR 是稳定接口：改动会影响规范化层、编译层、检测引擎与快照测试，
// 修改前请先阅读 docs/规则翻译器.md。
package rule

// Source 规则来源。
type Source string

const (
	SourceSuricata Source = "suricata" // 由 Suricata 规则导入
	SourceBuiltin  Source = "builtin"  // 项目内置规则
	SourceCustom   Source = "custom"   // 管理员自定义
)

// Protocol 规则限定的协议。
type Protocol string

const (
	ProtoAny  Protocol = "any"  // 不限协议
	ProtoTCP  Protocol = "tcp"  // TCP
	ProtoUDP  Protocol = "udp"  // UDP
	ProtoICMP Protocol = "icmp" // ICMP
	ProtoHTTP Protocol = "http" // HTTP（应用层）
	ProtoDNS  Protocol = "dns"  // DNS
	ProtoTLS  Protocol = "tls"  // TLS
	ProtoSSH  Protocol = "ssh"  // SSH
)

// NetSpec 网络地址范围；any 用空 Networks 表示。
type NetSpec struct {
	Negate   bool     // true 表示取反（!）
	Networks []string // CIDR 或单 IP，如 "192.168.0.0/16"、"1.2.3.4"
}

// PortRange 端口区间（闭区间）。
type PortRange struct {
	From uint16 // 起始端口
	To   uint16 // 结束端口
}

// PortSpec 端口范围；Any 为 true 表示不限端口。
type PortSpec struct {
	Any    bool        // 是否不限端口
	Ports  []uint16    // 单个端口列表
	Ranges []PortRange // 端口区间列表
}

// FlowSpec 流向限定；空串表示不限定。
type FlowSpec string

const (
	FlowToServer    FlowSpec = "to_server"   // 客户端 → 服务端
	FlowFromClient  FlowSpec = "from_client" // 同 to_server（Suricata 两种写法）
	FlowEstablished FlowSpec = "established" // 仅已建立连接的流
	FlowStateless   FlowSpec = "stateless"   // 无状态匹配
)

// ConditionKind 单个匹配条件的类型。
type ConditionKind string

const (
	CondContent ConditionKind = "content" // 内容匹配
	CondPCRE    ConditionKind = "pcre"    // 正则匹配
)

// Buffer 内容匹配的目标字段。
type Buffer string

const (
	BufPayload        Buffer = "payload"          // 整个载荷（默认）
	BufHTTPURI        Buffer = "http_uri"         // HTTP 请求 URI
	BufHTTPHeader     Buffer = "http_header"      // HTTP 头
	BufHTTPMethod     Buffer = "http_method"      // HTTP 方法
	BufHTTPClientBody Buffer = "http_client_body" // HTTP 请求体
	BufDNSQuery       Buffer = "dns_query"        // DNS 查询名
	BufTLSSNI         Buffer = "tls_sni"          // TLS SNI
)

// CondFlags 条件修饰标志（位掩码）。
type CondFlags uint8

const (
	FlagNoCase      CondFlags = 1 << 0 // 大小写不敏感
	FlagNegate      CondFlags = 1 << 1 // 取反（!）
	FlagFastPattern CondFlags = 1 << 2 // 指定为快速匹配模式
)

// Rule 一条规则（翻译后的内部表示）。
type Rule struct {
	ID         string   // 内部 ID，如 "suricata-2100498"
	Source     Source   // 规则来源
	SourceID   string   // 原始规则 sid，保证可回溯
	Name       string   // 规则名（Suricata 的 msg）
	Category   string   // 分类树节点（web/pwn/scanner/...）
	Severity   string   // 严重度（由 classtype/priority 映射）
	References []string // 参考（CVE / URL / ATT&CK）
	Enabled    bool     // 是否默认启用

	Match  Match  // 匹配条件
	Action Action // 命中动作
}

// Match 一条规则的匹配条件。
type Match struct {
	Proto      Protocol    // 限定的协议
	SrcIP      NetSpec     // 源地址范围
	DstIP      NetSpec     // 目的地址范围
	SrcPort    PortSpec    // 源端口范围
	DstPort    PortSpec    // 目的端口范围
	Flow       FlowSpec    // 流向限定
	Conditions []Condition // 内容/正则等条件，多个条件默认 AND
}

// Condition 单个匹配条件。
type Condition struct {
	Kind   ConditionKind // 条件类型（content / pcre）
	Buffer Buffer        // 匹配的目标字段
	Value  string        // 内容原文 或 正则表达式
	Flags  CondFlags     // 修饰标志
	Offset int           // 起始偏移（content 的 offset）
	Depth  int           // 匹配深度（content 的 depth）
}

// Action 命中后产生的事件。
type Action struct {
	Kind       string  // 事件类型，如 "sql_injection"
	Severity   string  // 严重度
	Weight     int     // 供态势引擎评分的权重
	Confidence float64 // 置信度（0~1）
}
