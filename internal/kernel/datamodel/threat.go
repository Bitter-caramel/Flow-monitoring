package datamodel

import "time"

// ThreatLevel 态势威胁等级（四级实现档位，对应 v0.3 第 9.3 节）。
//
// 对外 UI 呈现为三级（危急/攻击/正常 + 默认关注），
// 内部实现增加 L0 危急档，专门承载"大规模攻击 + 大批量封禁 + 自保护"场景。
type ThreatLevel int

const (
	// L0Critical 危急：疑似大规模攻击 / 自保护触发。
	// 触发：大规模同型攻击计数 ≥ N 或资源水位越界。
	// 动作：批量封禁（分批+背压+可回滚清单）+ 自我保护降采样 + 通知管理员。
	L0Critical ThreatLevel = 0

	// L1Attack 攻击：确认存在攻击行为。
	// 触发：评分 ≥ 中阈值；或连续 M 个异常特征。
	// 动作：收集攻击链、还原流程、告警推送；按策略处置（先模拟）。
	L1Attack ThreatLevel = 1

	// L2Attention 关注（默认起始态）：有可疑行为、暂不确认攻击。
	// 触发：默认起始；评分在低~中区间。
	// 动作：保留证据、按需记录、不自动处置；异常特征计数+1。
	L2Attention ThreatLevel = 2

	// L3Normal 正常：无攻击特征。
	// 触发：评分 < 低阈值。
	// 动作：仅统计记录，采样率可降，告警关闭，Subject 冷却回收。
	L3Normal ThreatLevel = 3
)

// String 等级的人类可读名称（用于日志/UI）。
func (l ThreatLevel) String() string {
	switch l {
	case L0Critical:
		return "Critical"
	case L1Attack:
		return "Attack"
	case L2Attention:
		return "Attention"
	case L3Normal:
		return "Normal"
	}
	return "Unknown"
}

// SubjState Subject 状态机状态（v0.3 第 9.4 节升降级状态机）。
//
//	                                     ┌─(评分≥升阈值, 持续T1)─→ rising ──(连续M个窗口)─→ sustained
//	                                     │                                  │
//	                                     │                                  ├─(评分<降阈值, 持续T2)─→ decaying
//	tracking ──(评分≥升阈值, 持续T1)─→ rising                                  │                          │
//	   │                                     │                                  ↓                          ↓
//	   │                                     ↓                                  banned               tracking(对象瘦身/回收)
//	 冷却中(冷却期后回收)←──────── banned ◀───(处置执行)
type SubjState int

const (
	SubjTracking  SubjState = iota // 跟踪中：默认状态
	SubjRising                     // 上升中：连续评分高，但未达持续阈值
	SubjSustained                  // 持续：M 个窗口都命中升阈值
	SubjDecaying                   // 衰减中：评分降至降阈值以下，正在瘦身
	SubjBanned                     // 已处置：动作已执行，处于冷却期
	SubjCooling                    // 冷却中：处置动作冷却期内
)

// String 状态名。
func (s SubjState) String() string {
	switch s {
	case SubjTracking:
		return "tracking"
	case SubjRising:
		return "rising"
	case SubjSustained:
		return "sustained"
	case SubjDecaying:
		return "decaying"
	case SubjBanned:
		return "banned"
	case SubjCooling:
		return "cooling"
	}
	return "unknown"
}

// ThreatScore 加权累加 + 半衰衰减的评分模型。
//
// 公式：Score(t) = Σ feature.weight × recency_decay × confidence
// 设计参考 v0.3 第 9.5 节。
type ThreatScore struct {
	Value         float64       // 当前评分（0-100）
	Confidence    float64       // 置信度（0-1）
	UpdatedAt     time.Time     // 最后一次更新时间
	DecayHalfLife time.Duration // 半衰期（默认 5min，参考 v0.3 第 9.9 节）
}

// Subject IP 聚合对象：态势感知的主对象。
//
// 对应 v0.3 架构第 9.2 节 Subject 结构（"IP 级有状态"层级）：
//   - 由 situation-engine 维护，带评分、状态、证据与冷却
//   - 以 srcIP→(dstIP) 为键入并发表
//   - 每个保护目标最多维护可配置上限的活跃 Subject，超限走资源保护
type Subject struct {
	Key          string            // srcIP+dstIP+协议族聚合键
	SrcIP        uint32            // 攻击侧 IP
	DstIP        uint32            // 保护目标 IP，0=任意目标
	FlowIndex    map[string]uint64 // 下属流 ID → 包数（受水位限制）
	Score        ThreatScore
	Level        ThreatLevel // 1/2/3/0（L1/L2/L3/L0）
	State        SubjState   // tracking/rising/sustained/decaying/banned/cooling
	Evidences    []Evidence  // 证据链（见 Evidence）
	Banned       bool        // 是否已处置
	BannedAt     *time.Time  // 处置时间
	UpdatedAt    time.Time   // 最后活跃时间
	CoolingUntil time.Time   // 冷却到期时间（处置动作后）
}

// Evidence 证据链单条记录。
//
// 对应 v0.3 第 9.5 节："每个 Evidence 记录 时间/特征类型/源证据/关联 Subject"。
// 是攻击链收集的基本单位。
type Evidence struct {
	Time       time.Time
	Kind       string // scan/brute/tunnel/beacon/rule_hit/stat_anomaly
	SubjectKey string // 关联 Subject.Key
	SrcIP      uint32
	DstIP      uint32
	Weight     float64 // 该证据的权重
	Confidence float64 // 置信度（0-1）
	Payload    []byte  // 证据引用（包号/规则ID，二进制编码后写）
	PacketNo   int     // 关联的包号
	RuleID     string  // 关联的规则 ID（若有）
	AlertID    string  // 关联的告警 ID（若有）
}

// FeatureEvent 检测源向 situation-engine 注入的特征事件。
//
// 对应 v0.3 第 9.8 节 SituationAPI.ReportEvent 入参。
// 特征来源：行为检测/suricata 适配/统计异常/规则命中。
type FeatureEvent struct {
	Time       time.Time
	Kind       string // scan/brute/tunnel/beacon/rule_hit/stat_anomaly
	SubjectKey string
	SrcIP      uint32
	DstIP      uint32
	Weight     float64
	Confidence float64
	Payload    []byte // 证据引用（包号/规则ID）
}

// LevelChange 态势等级变化（推送给前端）。
// 对应 v0.3 SubscribeLevel 返回的事件类型。
type LevelChange struct {
	SubjectKey string
	From       ThreatLevel
	To         ThreatLevel
	At         time.Time
	Reason     string // 升降级原因（评分/窗口计数/自保护...）
}

// ResourceReport 资源水位报告。
// 对应 v0.3 第 9.7 节资源自保护的硬机制。
type ResourceReport struct {
	ActiveSubjects    int           // 当前活跃 Subject 数量
	MaxSubjects       int           // 配置上限
	EventQueueDepth   int           // 特征事件队列深度
	EventQueueMax     int           // 队列上限
	DroppedEvents     uint64        // 因背压丢弃的低优先级特征数
	AvgProcessLatency time.Duration // 平均处理时延
	SelfProtectActive bool          // 是否处于自保护降采样模式
}
