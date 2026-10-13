package collect

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"flow-monitoring/internal/modules/alert"
	"flow-monitoring/internal/modules/parse/pcapng"
)

// RangeReader 能按时间范围读回原始帧（磁盘留存实现它；将来的输入抓包文件也能实现）。
type RangeReader interface {
	ReadRange(from, to time.Time) ([]Frame, bool, error)
}

// EvidenceOptions 证据提取配置。
type EvidenceOptions struct {
	Dir       string        // 证据根目录（默认 "evidence"）
	CaptureID string        // 本次抓包标识（子目录名）
	LinkType  int           // 链路类型（1 = Ethernet）
	Window    time.Duration // 前后各多久（默认 5s）
	MaxBytes  int64         // 单文件上限（默认 256<<20）
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
}

// EvidenceMeta 是证据文件的边车（自描述）。
type EvidenceMeta struct {
	CaptureID  string     `json:"capture_id"`
	File       string     `json:"file"`
	From       time.Time  `json:"from"`
	To         time.Time  `json:"to"`
	Packets    int        `json:"packets"`
	Bytes      int64      `json:"bytes"`
	Sources    []string   `json:"sources"` // 含 "disk" / "ring"
	Incomplete bool       `json:"incomplete"`
	Reason     string     `json:"reason,omitempty"`
	Alerts     []AlertRef `json:"alerts"`
}

// evidenceWindow 是一个待收集窗口：时间区间 [from, to] 与落在其中的告警。
type evidenceWindow struct {
	from   time.Time
	to     time.Time
	alerts []AlertRef
}

// EvidenceCollector 把命中告警前后的原始帧切出来、独立另存成 pcapng + 自描述边车。
//
// 落盘策略严格遵循"磁盘留存是不淘汰的账本、环形缓冲只是安全网"：
//   - 磁盘能完整覆盖窗口 -> 只读磁盘（sources=["disk"]，incomplete=false）；
//   - 磁盘不完整 -> 才用环补缺口，按包号 No 去重（同号优先磁盘），sources 含 "ring"；
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
	}

	for _, w := range e.pending {
		// 新告警的窗口 [from,to] 与已有待收集窗口重叠 -> 并入。
		if !to.Before(w.from) && !from.After(w.to) {
			if to.After(w.to) {
				w.to = to
			}
			w.alerts = append(w.alerts, ref)
			return
		}
	}

	e.pending = append(e.pending, &evidenceWindow{
		from:   from,
		to:     to,
		alerts: []AlertRef{ref},
	})
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
			// ② 磁盘不完整 -> 用环补缺口，按包号去重（同号优先磁盘）。
			var ringFrames []Frame
			if e.ring != nil {
				ringFrames = e.ring.Slice(from, to)
			}
			frames = mergeByNo(diskFrames, ringFrames)
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

	// 结果按时间升序稳定排序（时间相同保持原顺序：磁盘帧在前）。
	sort.SliceStable(frames, func(i, j int) bool {
		return frames[i].Time.Before(frames[j].Time)
	})

	// 只有"磁盘报告完整覆盖"时才 incomplete=false；disk==nil 也算不完整。
	incomplete := !complete

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

	var notes []string
	if len(frames) == 0 {
		notes = append(notes, "两侧都没有数据（磁盘与内存环均为空）")
	}
	if !complete && len(frames) > 0 && e.disk != nil {
		notes = append(notes, "磁盘未完整覆盖窗口（有段被轮转删除或尚未落盘），已用内存环补缺口")
	}
	if truncated {
		notes = append(notes, "达到 MaxBytes 上限，已截断")
	}

	meta := EvidenceMeta{
		CaptureID:  e.capID,
		File:       filepath.Base(pcapPath),
		From:       from,
		To:         to,
		Packets:    packets,
		Bytes:      fileBytes,
		Sources:    sources,
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

// mergeByNo 合并磁盘帧与环帧，去掉"同一帧"的重复，同一帧优先保留磁盘的那份。
//
// ★ 与题面不一致的说明（以现有代码为准）：题面要求"按包号 No 去重"，但本仓库的
// SegmentStore 把每段写成独立的 pcapng 段文件，而 pcapng 格式并不保存包序号——
// pcapng.Parse 会对每个段文件从 1 重新编号。因此磁盘帧的 No 是"段内局部号"，
// 与 Ring 帧的"全局包号"根本不是同一坐标系，直接按 No 比对既去不掉重复、
// 还可能误删真正不同的帧。
//
// 这里改用"帧时间（微秒，与磁盘存储分辨率一致）+ 帧字节哈希"来识别同一帧：
// 语义仍是"同一帧优先磁盘"，既去掉重复又不会误删真正不同的帧。
func mergeByNo(disk, ring []Frame) []Frame {
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
