package situation

import (
	"sort"
	"sync"
	"time"
)

// 默认配置：5 分钟滑动窗口、30/100/300 三档阈值。
const (
	defaultWindowSec       = 300
	defaultLowThreshold    = int64(30)
	defaultMediumThreshold = int64(100)
	defaultHighThreshold   = int64(300)

	// maxTopRules 是每个 IP 在响应里携带的 top_rules 条数上限。
	maxTopRules = 5
)

// 威胁等级。none 表示"分数未达最低阈值"（仍可能有少量命中）。
const (
	levelNone   = "none"
	levelLow    = "low"
	levelMedium = "medium"
	levelHigh   = "high"
)

// engineConfig 是评分引擎的私有配置。
type engineConfig struct {
	window time.Duration // 滑动窗口长度
	low    int64         // low 下限（含）
	medium int64         // medium 下限（含）
	high   int64         // high 下限（含）
}

// defaultEngineConfig 返回出厂默认配置。
func defaultEngineConfig() engineConfig {
	return engineConfig{
		window: time.Duration(defaultWindowSec) * time.Second,
		low:    defaultLowThreshold,
		medium: defaultMediumThreshold,
		high:   defaultHighThreshold,
	}
}

// hit 是一次命中记录（只保留窗口内的）。
//
// ★ at 使用"收到事件的时间"而非载荷里的 time：窗口滑动按墙上时钟，
//
//	这样即使载荷时间来自旧的一次运行，也不会把过期事件永久计入。
type hit struct {
	at     time.Time
	weight int64
	rule   string
}

// ipState 是单个源 IP 的聚合状态（全部字段仅在 engine.mu 持有下访问）。
type ipState struct {
	hits       []hit          // 按 at 升序（at = now，天然单调）
	score      int64          // Σ weight × hitCount，不封顶
	ruleCounts map[string]int // rule_id → 窗口内命中次数
	level      string         // 当前等级（levelNone/low/medium/high）
}

// levelChange 是 situation.level 事件的载荷。
type levelChange struct {
	SrcIP     string   `json:"src_ip"`
	Level     string   `json:"level"`
	Prev      string   `json:"prev"`
	Score     int64    `json:"score"`
	Hits      int      `json:"hits"`
	Rules     int      `json:"rules"`
	WindowSec int      `json:"window_sec"`
	TopRules  []string `json:"top_rules"`
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
	At        string   `json:"at"`
}

// item 是 GET /api/situation 的列表项。
type item struct {
	SrcIP     string   `json:"src_ip"`
	Level     string   `json:"level"`
	Score     int64    `json:"score"`
	Hits      int      `json:"hits"`
	Rules     int      `json:"rules"`
	TopRules  []string `json:"top_rules"`
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
}

// engineStats 是评分引擎的运行统计快照。
type engineStats struct {
	WindowSec    int    `json:"window_sec"`
	TrackedIPs   int    `json:"tracked_ips"`
	LevelChanges uint64 `json:"level_changes"`
	Received     uint64 `json:"received"`
	DecodeErrors uint64 `json:"decode_errors"`
	TopScore     int64  `json:"top_score"`
}

// engine 是按源 IP 聚合评分的核心。
//
// 并发约定：所有状态读写都在 mu 下完成；对外方法返回需要发布的事件，
// 由调用方**在锁外**发布（Host.Publish 可能阻塞，持锁发事件会卡住消费/查询）。
type engine struct {
	mu sync.Mutex

	cfg engineConfig
	ips map[string]*ipState

	now func() time.Time // 可注入时钟（测试用）

	received     uint64
	decodeErrors uint64
	levelChanges uint64
}

// newEngine 创建评分引擎。
func newEngine(cfg engineConfig) *engine {
	return &engine{
		cfg: normalizeEngineConfig(cfg),
		ips: make(map[string]*ipState),
		now: time.Now,
	}
}

// normalizeEngineConfig 兜住非法配置（窗口/阈值必须为正且递增）。
func normalizeEngineConfig(cfg engineConfig) engineConfig {
	if cfg.window <= 0 {
		cfg.window = time.Duration(defaultWindowSec) * time.Second
	}
	if cfg.low <= 0 {
		cfg.low = defaultLowThreshold
	}
	if cfg.medium <= cfg.low {
		cfg.medium = cfg.low + 1
	}
	if cfg.high <= cfg.medium {
		cfg.high = cfg.medium + 1
	}
	return cfg
}

// configure 在模块启动时应用配置并清空历史状态。
func (e *engine) configure(cfg engineConfig) {
	e.mu.Lock()
	e.cfg = normalizeEngineConfig(cfg)
	e.ips = make(map[string]*ipState)
	e.received = 0
	e.decodeErrors = 0
	e.levelChanges = 0
	e.mu.Unlock()
}

// incDecodeError 记录一次载荷解析失败。
func (e *engine) incDecodeError() {
	e.mu.Lock()
	e.decodeErrors++
	e.mu.Unlock()
}

// record 记录一次命中，返回随之产生的等级变化事件。
//
// 计分规则：每次命中都累计 weight（同一规则反复命中也要算），int64 不封顶。
func (e *engine) record(srcIP, ruleID string, weight int64) []levelChange {
	if weight < 0 {
		weight = 0
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.now()
	e.received++

	st := e.ips[srcIP]
	if st == nil {
		st = &ipState{
			ruleCounts: make(map[string]int),
			level:      levelNone,
		}
		e.ips[srcIP] = st
	}

	// 先滚动窗口（含过期清理），再加本次命中。
	e.pruneLocked(st, now)

	st.hits = append(st.hits, hit{at: now, weight: weight, rule: ruleID})
	st.score += weight
	if ruleID != "" {
		st.ruleCounts[ruleID]++
	}

	return e.applyLevelLocked(srcIP, st, now)
}

// snapshot 返回当前威胁视图（按 score 降序），并顺带滚动窗口/清理过期 IP。
//
// 返回的等级变化事件由调用方在锁外发布。
func (e *engine) snapshot() ([]item, []levelChange) {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.now()
	items := make([]item, 0, len(e.ips))
	var changes []levelChange

	for srcIP, st := range e.ips {
		e.pruneLocked(st, now)
		if len(st.hits) == 0 {
			// 全部命中过期：先发降级到 none，再从 map 删除，防止无界增长。
			changes = append(changes, e.applyLevelLocked(srcIP, st, now)...)
			delete(e.ips, srcIP)
			continue
		}

		changes = append(changes, e.applyLevelLocked(srcIP, st, now)...)
		items = append(items, e.itemLocked(srcIP, st))
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].Score != items[j].Score {
			return items[i].Score > items[j].Score
		}
		return items[i].SrcIP < items[j].SrcIP
	})
	return items, changes
}

// stats 返回统计快照（只读，不滚动窗口）。
func (e *engine) stats() engineStats {
	e.mu.Lock()
	defer e.mu.Unlock()

	var top int64
	for _, st := range e.ips {
		if st.score > top {
			top = st.score
		}
	}
	return engineStats{
		WindowSec:    int(e.cfg.window / time.Second),
		TrackedIPs:   len(e.ips),
		LevelChanges: e.levelChanges,
		Received:     e.received,
		DecodeErrors: e.decodeErrors,
		TopScore:     top,
	}
}

// pruneLocked 移除早于 now-window 的命中（要求持有 mu）。
func (e *engine) pruneLocked(st *ipState, now time.Time) {
	cutoff := now.Add(-e.cfg.window)
	i := 0
	for i < len(st.hits) && st.hits[i].at.Before(cutoff) {
		h := st.hits[i]
		st.score -= h.weight
		if h.rule != "" {
			if c := st.ruleCounts[h.rule]; c > 1 {
				st.ruleCounts[h.rule] = c - 1
			} else {
				delete(st.ruleCounts, h.rule)
			}
		}
		i++
	}
	if i > 0 {
		st.hits = st.hits[i:]
	}
	if st.score < 0 {
		st.score = 0
	}
}

// applyLevelLocked 根据当前分数重算等级；变化时产生一条事件（要求持有 mu）。
func (e *engine) applyLevelLocked(srcIP string, st *ipState, at time.Time) []levelChange {
	next := e.levelOf(st.score)
	if next == st.level {
		return nil
	}
	prev := st.level
	st.level = next
	e.levelChanges++
	return []levelChange{e.makeChange(srcIP, st, prev, next, at)}
}

// levelOf 把分数映射到等级（阈值可配置）。
func (e *engine) levelOf(score int64) string {
	switch {
	case score >= e.cfg.high:
		return levelHigh
	case score >= e.cfg.medium:
		return levelMedium
	case score >= e.cfg.low:
		return levelLow
	default:
		return levelNone
	}
}

// makeChange 基于当前状态构造事件载荷（要求持有 mu）。
func (e *engine) makeChange(srcIP string, st *ipState, prev, next string, at time.Time) levelChange {
	hits := len(st.hits)
	first, last := "", ""
	if hits > 0 {
		first = formatTimestamp(st.hits[0].at)
		last = formatTimestamp(st.hits[hits-1].at)
	}
	return levelChange{
		SrcIP:     srcIP,
		Level:     next,
		Prev:      prev,
		Score:     st.score,
		Hits:      hits,
		Rules:     len(st.ruleCounts),
		WindowSec: int(e.cfg.window / time.Second),
		TopRules:  topRules(st.ruleCounts),
		FirstSeen: first,
		LastSeen:  last,
		At:        formatTimestamp(at),
	}
}

// itemLocked 构造列表项（要求持有 mu）。
func (e *engine) itemLocked(srcIP string, st *ipState) item {
	hits := len(st.hits)
	first, last := "", ""
	if hits > 0 {
		first = formatTimestamp(st.hits[0].at)
		last = formatTimestamp(st.hits[hits-1].at)
	}
	return item{
		SrcIP:     srcIP,
		Level:     st.level,
		Score:     st.score,
		Hits:      hits,
		Rules:     len(st.ruleCounts),
		TopRules:  topRules(st.ruleCounts),
		FirstSeen: first,
		LastSeen:  last,
	}
}

// topRules 返回命中次数最多的规则（次数降序、同次数按 rule_id 升序）。
// 返回值恒为非 nil 切片，保证 JSON 序列化成 [] 而不是 null。
func topRules(counts map[string]int) []string {
	out := make([]string, 0, len(counts))
	for rule := range counts {
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool {
		ci, cj := counts[out[i]], counts[out[j]]
		if ci != cj {
			return ci > cj
		}
		return out[i] < out[j]
	})
	if len(out) > maxTopRules {
		out = out[:maxTopRules]
	}
	return out
}

// formatTimestamp 把时间格式化为 RFC3339（纳秒精度），前端可直接 new Date()。
func formatTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
