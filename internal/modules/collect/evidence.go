package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/modules/alert"
	"flow-monitoring/internal/modules/parse/pcapng"
)

// RangeReader 能按时间范围读回原始帧（磁盘留存实现它；将来的输入抓包文件也能实现）。
type RangeReader interface {
	ReadRange(from, to time.Time) ([]Frame, bool, error)
}

// Endpoint 连接的一端（IP + 端口）。
//
// ★ 这是本包自己的最小投影：故意不复用 storage.Endpoint，避免 collect 依赖 storage 包
// （模块之间不许互相耦合）。
type Endpoint struct {
	IP   string
	Port uint16
}

// PacketRef 指向"某个 capture 文件里的第 No 个包"：库里只存元数据，
// 原始字节在 packetstore 的文件里，取帧要凭这两个字段。
type PacketRef struct {
	CaptureID string
	No        int
}

// ConnPacket 是"按连接查包"结果的最小投影（只取取帧与排序需要的字段）。
type ConnPacket struct {
	CaptureID string
	No        int
	Time      time.Time
}

// FlowQuerier 按连接（两个端点、双向）查包元数据；total 是匹配总数（可能大于本页）。
// 装配层用 storage.PacketFlowQuerier（11-7b）适配它。
type FlowQuerier interface {
	ListByConn(ctx context.Context, a, b Endpoint, limit int) (items []ConnPacket, total int, err error)
}

// FrameFetcher 按 (captureID, No) 取回**原始帧**。
// 装配层用 packetstore.ReadRaw + pcapng.Parse 适配它（本包不做解析）。
type FrameFetcher interface {
	FetchFrames(ctx context.Context, refs []PacketRef) ([]Frame, error)
}

// EvidenceOptions 证据提取配置。
type EvidenceOptions struct {
	Dir       string        // 证据根目录（默认 "evidence"）
	CaptureID string        // 本次抓包标识（子目录名）
	LinkType  int           // 链路类型（1 = Ethernet）
	Window    time.Duration // 前后各多久（默认 5s）
	MaxBytes  int64         // 单文件上限（默认 256<<20）
	Querier   FlowQuerier   // 可选：按连接查库（nil = 不查库）
	Frames    FrameFetcher  // 可选：按 (captureID, No) 取原始帧（nil = 不取库里的帧）
}

const (
	// defaultEvidenceDir 是证据根目录的默认值。
	defaultEvidenceDir = "evidence"
	// defaultEvidenceWindow 是证据窗口半径的默认值（前后各 5s）。
	defaultEvidenceWindow = 5 * time.Second
	// defaultEvidenceMaxBytes 是单个证据文件的默认字节上限（256MB）。
	defaultEvidenceMaxBytes = int64(256 << 20)
	// evidenceTimeLayout 是证据文件名里窗口起点时间的格式。
	evidenceTimeLayout = "20060102T150405"
)

// AlertRef 是边车里记录的"本次证据覆盖到的告警"。
type AlertRef struct {
	RuleID  string    `json:"rule_id"`
	Name    string    `json:"name"`
	Time    time.Time `json:"time"`
	PktNo   int       `json:"pkt_no"`
	FlowKey string    `json:"flow_key"`
	// ConnKey 是**对称的双向连接键**（datamodel.ConnKey），把同一条连接的两个方向归到一处；
	// 证据导出靠它取回“整条连接”的帧（不依赖 IPv4 才有的 StreamID）。
	ConnKey string `json:"conn_key,omitempty"`
}

// EvidenceMeta 是证据文件的边车（自描述）。
type EvidenceMeta struct {
	CaptureID  string     `json:"capture_id"`
	File       string     `json:"file"`
	From       time.Time  `json:"from"`
	To         time.Time  `json:"to"`
	Packets    int        `json:"packets"`
	Bytes      int64      `json:"bytes"`
	Sources    []string   `json:"sources"` // 含 "disk" / "ring" / "ring-conn"
	ConnKeys   []string   `json:"conn_keys,omitempty"`
	Incomplete bool       `json:"incomplete"`
	Reason     string     `json:"reason,omitempty"`
	Alerts     []AlertRef `json:"alerts"`
}

// evidenceWindow 是一个待收集窗口：时间区间 [from, to] 与落在其中的告警。
type evidenceWindow struct {
	from   time.Time
	to     time.Time
	alerts []AlertRef
	// connKeys 是本窗口涉及的全部连接键（对称双向）。11-7c-1 用它把证据从“窗口内的帧”
	// 升级为“这些连接在内存环里的全部帧”。
	connKeys map[string]struct{}
	// connEP 是连接键 -> 该连接的两个端点（用于"按连接查库"补齐）。同一个键只记一次。
	connEP map[string][2]Endpoint
}

// addConnKey 记录本窗口涉及的连接键；空串不加入（避免脏键）。惰性建 map，兼容零值窗口。
func (w *evidenceWindow) addConnKey(k string) {
	if k == "" {
		return
	}
	if w.connKeys == nil {
		w.connKeys = make(map[string]struct{})
	}
	w.connKeys[k] = struct{}{}
}

// addConnEndpoints 记录连接键对应的两个端点（供"按连接查库"用）；空键不记。
// 同一个键重复覆盖无所谓：连接键由端点决定。
func (w *evidenceWindow) addConnEndpoints(k string, a, b Endpoint) {
	if k == "" {
		return
	}
	if w.connEP == nil {
		w.connEP = make(map[string][2]Endpoint)
	}
	w.connEP[k] = [2]Endpoint{a, b}
}

// sortedConnKeys 返回窗口里的连接键（字典序），保证遍历顺序稳定、便于测试与复现。
func sortedConnKeys(w *evidenceWindow) []string {
	out := make([]string, 0, len(w.connKeys))
	for k := range w.connKeys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ringEarliestByConn 返回环里每个“有连接键的帧”的连接键 -> 该连接在环内最早帧时间。
//
// ★ 这是**推断**而非精确查询：Ring 未暴露“最老帧时间”，本包也不改 ring.go；这里只能遍历
// ConnKeys 看**已建索引**（连接键非空）的帧。未建索引的帧（空键）看不到，故该结果表示
// “已建索引帧范围内的最老时间”。宁可据此如实标注不完整，也不假装完整。
func (e *EvidenceCollector) ringEarliestByConn() map[string]time.Time {
	if e.ring == nil {
		return nil
	}
	out := make(map[string]time.Time)
	for _, k := range e.ring.ConnKeys() {
		fs := e.ring.FramesByConn(k) // 已按时间升序
		if len(fs) == 0 {
			continue
		}
		out[k] = fs[0].Time
	}
	return out
}

// truncatedConnKeys 返回“很可能已被环淘汰掉更早帧”的连接键（有序）。
//
// 判据（推断）：某连接在环内最早帧 <= 环里所有连接的最早帧——即它恰好落在可见帧的最老端，
// 说明该连接更早的帧很可能已被按容量淘汰。全局最早帧就是所有连接最早帧的最小值，故这等价于
// “该连接包含环里可见的最老帧”。宁可标注，不装作完整。
func truncatedConnKeys(earliestByConn map[string]time.Time, connKeys map[string]struct{}) []string {
	if len(earliestByConn) == 0 || len(connKeys) == 0 {
		return nil
	}
	var oldest time.Time
	first := true
	for _, t := range earliestByConn {
		if first || t.Before(oldest) {
			oldest = t
			first = false
		}
	}
	var out []string
	for k := range connKeys {
		t, ok := earliestByConn[k]
		if !ok {
			continue
		}
		if !t.After(oldest) { // t <= oldest（= 全局最早）
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// EvidenceCollector 把命中告警前后的原始帧切出来、独立另存成 pcapng + 自描述边车。
//
// 落盘策略严格遵循"磁盘留存是不淘汰的账本、环形缓冲只是安全网"：
//   - 磁盘能完整覆盖窗口 -> 只读磁盘（sources=["disk"]，incomplete=false）；
//   - 磁盘不完整 -> 才用环补缺口，按帧时间 + 帧字节哈希去重（pcapng 不保存包序号，磁盘帧的 No 是段内局部号），sources 含 "ring"；
//   - 两边都没有 -> 仍产出文件，incomplete=true 且 Reason 写清原因。
type EvidenceCollector struct {
	mu    sync.Mutex
	dir   string
	capID string
	link  int

	window   time.Duration
	maxBytes int64

	ring *Ring
	disk RangeReader

	// 可选依赖（nil = 不启用该路，行为与既有完全一致）：
	// querier 按连接查库元数据，fetcher 按 (captureID, No) 取回库里的原始帧。
	querier FlowQuerier
	fetcher FrameFetcher

	pending []*evidenceWindow
}

// NewEvidence 创建证据提取器。ring 可为 nil（只用磁盘）；disk 也可为 nil（只用内存）。
func NewEvidence(opts EvidenceOptions, ring *Ring, disk RangeReader) *EvidenceCollector {
	if opts.Dir == "" {
		opts.Dir = defaultEvidenceDir
	}
	if opts.Window <= 0 {
		opts.Window = defaultEvidenceWindow
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = defaultEvidenceMaxBytes
	}
	if opts.LinkType <= 0 {
		opts.LinkType = 1 // 默认 Ethernet
	}
	return &EvidenceCollector{
		dir:      opts.Dir,
		capID:    opts.CaptureID,
		link:     opts.LinkType,
		window:   opts.Window,
		maxBytes: opts.MaxBytes,
		ring:     ring,
		disk:     disk,
		querier:  opts.Querier,
		fetcher:  opts.Frames,
	}
}

// OnAlert 登记一条告警：落在已有待收集窗口里（即两条窗口重叠）就并入，
// 并把窗口终点往后延；否则开一个新窗口。
func (e *EvidenceCollector) OnAlert(ev alert.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()

	t := ev.Alert.Time
	from := t.Add(-e.window)
	to := t.Add(e.window)

	ref := AlertRef{
		RuleID:  ev.Alert.RuleID,
		Name:    ev.Alert.Name,
		Time:    t,
		PktNo:   ev.Alert.PktNo,
		FlowKey: ev.Alert.FlowKey,
		// ★ 11-7c-1：用端点算对称连接键，供导出取回“整条连接”。
		ConnKey: datamodel.ConnKey(ev.Alert.SrcIP, ev.Alert.SrcPort, ev.Alert.DstIP, ev.Alert.DstPort),
	}

	// ★ 11-7c-2：连接的两个端点（供“按连接查库”补齐用）。空键不记，保持既有行为。
	ep := [2]Endpoint{
		{IP: ev.Alert.SrcIP, Port: ev.Alert.SrcPort},
		{IP: ev.Alert.DstIP, Port: ev.Alert.DstPort},
	}

	for _, w := range e.pending {
		// 新告警的窗口 [from,to] 与已有待收集窗口重叠 -> 并入。
		if !to.Before(w.from) && !from.After(w.to) {
			if to.After(w.to) {
				w.to = to
			}
			w.alerts = append(w.alerts, ref)
			w.addConnKey(ref.ConnKey)
			w.addConnEndpoints(ref.ConnKey, ep[0], ep[1])
			return
		}
	}

	w := &evidenceWindow{
		from:   from,
		to:     to,
		alerts: []AlertRef{ref},
	}
	w.addConnKey(ref.ConnKey)
	w.addConnEndpoints(ref.ConnKey, ep[0], ep[1])
	e.pending = append(e.pending, w)
}

// Tick 关掉所有"已到期"（now >= 窗口终点）的待收集窗口并落盘，返回本次新产出的证据文件路径。
func (e *EvidenceCollector) Tick(now time.Time) ([]string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.flushPendingLocked(now, false)
}

// Close 关掉所有待收集窗口并落盘（收尾用）。
func (e *EvidenceCollector) Close() ([]string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.flushPendingLocked(time.Time{}, true)
}

// flushPendingLocked 落盘待收集窗口。all=false 时只落"已到期"的（now >= to）；
// all=true 时全部落盘。调用方必须已持有 e.mu。
func (e *EvidenceCollector) flushPendingLocked(now time.Time, all bool) ([]string, error) {
	out := make([]string, 0, len(e.pending))
	kept := e.pending[:0]
	var firstErr error

	for _, w := range e.pending {
		if !all && now.Before(w.to) {
			kept = append(kept, w)
			continue
		}
		path, err := e.flushWindow(w)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, path)
	}
	e.pending = kept
	return out, firstErr
}

// flushWindow 收集并落盘一个窗口，返回产出的 pcapng 路径。
func (e *EvidenceCollector) flushWindow(w *evidenceWindow) (string, error) {
	from, to := w.from, w.to

	var (
		frames   []Frame
		sources  []string
		complete bool
	)

	if e.disk != nil {
		diskFrames, diskComplete, err := e.disk.ReadRange(from, to)
		if err != nil {
			return "", err
		}
		complete = diskComplete
		if diskComplete {
			// ① 磁盘能完整覆盖窗口 -> 只读磁盘，零合并。
			frames = diskFrames
			sources = []string{"disk"}
		} else {
			// ② 磁盘不完整 -> 用环补缺口，按帧时间 + 帧字节哈希去重（同帧优先磁盘）。
			var ringFrames []Frame
			if e.ring != nil {
				ringFrames = e.ring.Slice(from, to)
			}
			frames = mergeFrames(diskFrames, ringFrames)
			sources = []string{"disk"}
			if len(ringFrames) > 0 {
				sources = append(sources, "ring")
			}
		}
	} else {
		// disk == nil -> 只用内存环。
		if e.ring != nil {
			frames = e.ring.Slice(from, to)
		}
		sources = []string{"ring"}
	}

	// ★ 11-7c-1：从“时间窗”升级为“整条连接”——把这些连接在环里的**全部**帧也取回来
	// （不受窗口时间限制）。环是按容量淘汰的，所以“环里有”就等于“内存里还留着”。
	if e.ring != nil && len(w.connKeys) > 0 {
		var connFrames []Frame
		for k := range w.connKeys { // ★ 遍历 map 顺序不定 ⇒ 收集后统一排序
			connFrames = append(connFrames, e.ring.FramesByConn(k)...)
		}
		if len(connFrames) > 0 {
			frames = mergeFrames(frames, connFrames) // 复用既有去重（时间 + 字节哈希）
			sources = append(sources, "ring-conn")   // ★ 新来源名，便于区分
		}
	}

	// 只有"磁盘报告完整覆盖"时才 incomplete=false；disk==nil 也算不完整。
	incomplete := !complete

	// notes 是"如实标注原因"的累加器（既有判据 + 库侧标注），最终拼成边车 Reason。
	var notes []string

	// ★ 11-7c-2：库侧补齐 —— 把该连接"已出留存窗口、已入库"的包元数据查回来，再按
	// (captureID, No) 取回原始帧并并入证据。只有同时给了 Querier 与 Frames 才启用；
	// 否则完全保持既有行为（nil = 不启用，sources 里也不会出现 "db"）。
	//
	// ★ ctx：flushWindow 现在没有 context 参数，为不改 Tick/Close 的签名，这里用
	// context.Background()（取舍：库侧查询不参与调用方取消；本任务只接入接口与流程）。
	if e.querier != nil && e.fetcher != nil && len(w.connEP) > 0 {
		ctx := context.Background()
		// dbPageLimit 是单次查询上限：避免一次拉过多元数据；total>len(items) 时如实标注不完整。
		const dbPageLimit = 1000
		var refs []PacketRef
		dbIncomplete := ""
		for _, k := range sortedConnKeys(w) { // ★ 顺序稳定，便于测试与复现
			ep, ok := w.connEP[k]
			if !ok {
				continue
			}
			items, total, err := e.querier.ListByConn(ctx, ep[0], ep[1], dbPageLimit)
			if err != nil {
				// 库侧查询失败不让整次取证失败：记入 notes/Reason，继续其余连接。
				notes = append(notes, fmt.Sprintf("按连接 %s 查库失败：%v", k, err))
				incomplete = true
				continue
			}
			for _, it := range items {
				refs = append(refs, PacketRef{CaptureID: it.CaptureID, No: it.No})
			}
			if total > len(items) {
				dbIncomplete = fmt.Sprintf("连接 %s 在库里还有更多包未取（本次上限 %d）", k, dbPageLimit)
			}
		}
		if len(refs) > 0 {
			dbFrames, err := e.fetcher.FetchFrames(ctx, refs)
			if err != nil {
				// 取帧失败同样不让整次取证失败：记入 notes/Reason。
				notes = append(notes, fmt.Sprintf("按 (captureID, No) 取库里的帧失败：%v", err))
				incomplete = true
			} else if len(dbFrames) > 0 {
				frames = mergeFrames(frames, dbFrames) // 复用既有去重（时间 + 字节哈希）
				sources = append(sources, "db")        // ★ 新来源名
			}
		}
		if dbIncomplete != "" {
			incomplete = true
			notes = append(notes, dbIncomplete)
		}
	}

	// 结果按时间升序稳定排序（时间相同保持原顺序：磁盘帧在前）。
	sort.SliceStable(frames, func(i, j int) bool {
		return frames[i].Time.Before(frames[j].Time)
	})

	dir := filepath.Join(e.dir, e.capID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("collect: mkdir evidence %s: %w", dir, err)
	}

	ruleID := "unknown"
	if len(w.alerts) > 0 {
		ruleID = sanitizeRuleID(w.alerts[0].RuleID)
	}
	base := fmt.Sprintf("%s-%s", from.Format(evidenceTimeLayout), ruleID)
	pcapPath := filepath.Join(dir, base+".pcapng")

	packets, fileBytes, truncated, err := e.writePCAP(pcapPath, frames)
	if err != nil {
		return "", err
	}

	if len(frames) == 0 {
		notes = append(notes, "两侧都没有数据（磁盘与内存环均为空）")
	}
	if !complete && len(frames) > 0 && e.disk != nil {
		notes = append(notes, "磁盘未完整覆盖窗口（有段被轮转删除或尚未落盘），已用内存环补缺口")
	}
	if truncated {
		notes = append(notes, "达到 MaxBytes 上限，已截断")
	}

	// ★ 11-7c-1：如实标注“连接的更早帧可能已被环淘汰”。在既有 incomplete 判据之外**追加**，
	// 不删既有判据。见 truncatedConnKeys 注释：这是**推断**（Ring 未暴露最老帧时间）。
	if e.ring != nil && len(w.connKeys) > 0 {
		if cut := truncatedConnKeys(e.ringEarliestByConn(), w.connKeys); len(cut) > 0 {
			incomplete = true
			for _, k := range cut {
				notes = append(notes, fmt.Sprintf("连接 %s 的更早帧不在内存环（可能已被留存窗口淘汰）", k))
			}
		}
	}

	// 连接键（对称、有序）写进边车，便于比对与检索。
	connKeys := make([]string, 0, len(w.connKeys))
	for k := range w.connKeys {
		connKeys = append(connKeys, k)
	}
	sort.Strings(connKeys)

	meta := EvidenceMeta{
		CaptureID:  e.capID,
		File:       filepath.Base(pcapPath),
		From:       from,
		To:         to,
		Packets:    packets,
		Bytes:      fileBytes,
		Sources:    sources,
		ConnKeys:   connKeys,
		Incomplete: incomplete,
		Reason:     strings.Join(notes, "；"),
		Alerts:     w.alerts,
	}

	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return "", fmt.Errorf("collect: marshal evidence meta: %w", err)
	}
	metaPath := strings.TrimSuffix(pcapPath, ".pcapng") + ".json"
	if err := os.WriteFile(metaPath, metaBytes, 0o644); err != nil {
		return "", fmt.Errorf("collect: write evidence meta %s: %w", metaPath, err)
	}

	return pcapPath, nil
}

// writePCAP 把 frames 写成 pcapng 文件，返回写入包数、文件字节数、是否因超过 MaxBytes 截断。
func (e *EvidenceCollector) writePCAP(path string, frames []Frame) (int, int64, bool, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, 0, false, fmt.Errorf("collect: create evidence %s: %w", path, err)
	}
	w, err := pcapng.NewWriter(f, e.link, 0)
	if err != nil {
		_ = f.Close()
		return 0, 0, false, fmt.Errorf("collect: init pcapng writer for %s: %w", path, err)
	}

	count := 0
	written := w.BytesWritten() // SHB + IDB
	truncated := false
	for i := range frames {
		// 预估写入该包后的总字节数（EPB 块 = 12 头尾 + 20 头 + 数据 + padding + 4 endofopt）。
		if written+epbBlockSize(len(frames[i].Data)) > e.maxBytes {
			truncated = true
			break
		}
		if err := w.WritePacket(frames[i].Time, frames[i].Data); err != nil {
			_ = w.Close()
			_ = f.Close()
			return count, written, truncated, fmt.Errorf("collect: write evidence packet: %w", err)
		}
		written = w.BytesWritten()
		count++
	}

	if err := w.Close(); err != nil { // 只 Flush，不关闭调用方的 io.Writer
		_ = f.Close()
		return count, written, truncated, fmt.Errorf("collect: flush evidence %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return count, written, truncated, fmt.Errorf("collect: close evidence %s: %w", path, err)
	}
	return count, written, truncated, nil
}

// epbBlockSize 返回一个 EPB 块写入后的字节数（含 4 字节对齐 padding）。
func epbBlockSize(dataLen int) int64 {
	pad := (4 - dataLen%4) % 4
	return int64(12 + 20 + dataLen + pad + 4)
}

// mergeFrames 合并磁盘帧与环帧，去掉"同一帧"的重复，同一帧优先保留磁盘的那份。
//
// ★ 与题面不一致的说明（以现有代码为准）：题面要求"按包号 No 去重"，但本仓库的
// SegmentStore 把每段写成独立的 pcapng 段文件，而 pcapng 格式并不保存包序号——
// pcapng.Parse 会对每个段文件从 1 重新编号。因此磁盘帧的 No 是"段内局部号"，
// 与 Ring 帧的"全局包号"根本不是同一坐标系，直接按 No 比对既去不掉重复、
// 还可能误删真正不同的帧。
//
// 这里改用"帧时间（微秒，与磁盘存储分辨率一致）+ 帧字节哈希"来识别同一帧：
// 语义仍是"同一帧优先磁盘"，既去掉重复又不会误删真正不同的帧。
func mergeFrames(disk, ring []Frame) []Frame {
	// 磁盘帧原样保留（不与其他磁盘帧互相去重），只把重复的环帧剔掉。
	out := make([]Frame, 0, len(disk)+len(ring))
	out = append(out, disk...)

	seen := make(map[string]int, len(disk))
	for _, f := range disk {
		seen[evidenceFrameKey(f)]++
	}
	for _, f := range ring {
		k := evidenceFrameKey(f)
		if seen[k] > 0 {
			seen[k]--
			continue
		}
		out = append(out, f)
	}
	return out
}

// evidenceFrameKey 生成跨来源识别"同一帧"的键。
func evidenceFrameKey(f Frame) string {
	h := fnv.New64a()
	_, _ = h.Write(f.Data)
	return fmt.Sprintf("%d/%d/%x", f.Time.UnixMicro(), len(f.Data), h.Sum64())
}

// sanitizeRuleID 把 RuleID 里可能非法的字符替换成 '_'，只保留字母数字、'-'、'_'、'.'。
func sanitizeRuleID(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "unknown"
	}
	return out
}
