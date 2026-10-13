package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/modules/parse/pcapng"
)

const (
	// defaultRootDir 是留存根目录的默认值。
	defaultRootDir = "capture"
	// defaultSegmentBytes 是段大小阈值的默认值（64MB）。
	defaultSegmentBytes = int64(64 << 20)
	// defaultRetentionSeg 是保留段数的默认值。
	defaultRetentionSeg = 100
	// segmentTimeLayout 是段名里起始时间的格式。
	segmentTimeLayout = "20060102T150405"
	// segmentIndexFile 是只追加索引文件名。
	segmentIndexFile = "index.jsonl"
)

// Options 留存配置。
type Options struct {
	RootDir           string // 留存根目录（默认 "capture"）
	CaptureID         string // 本次抓包/导入的标识（用作目录名与段名前缀）
	LinkType          int    // 链路类型（1 = Ethernet）
	SegmentBytes      int64  // 段大小阈值（默认 64<<20 = 64MB）
	RetentionSegments int    // 保留段数（默认 100；0 = 不限制）
	RetentionBytes    int64  // 保留总字节（默认 0 = 不限制）
	RetentionHours    int    // 保留小时（默认 0 = 不限制）
}

// DefaultOptions 返回默认配置。
func DefaultOptions() Options {
	return Options{
		RootDir:           defaultRootDir,
		LinkType:          1,
		SegmentBytes:      defaultSegmentBytes,
		RetentionSegments: defaultRetentionSeg,
	}
}

// SegmentInfo 一段留存文件的索引信息。
//
// Deleted 只作为"墓碑"记录：删段时不改写历史行，而是在 index.jsonl 追加一行
// Deleted=true 的相同段信息，保证索引文件只追加、可审计。
type SegmentInfo struct {
	No        int64     `json:"no"`
	Name      string    `json:"name"`
	Bytes     int64     `json:"bytes"`
	Packets   int64     `json:"packets"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Deleted   bool      `json:"deleted"`
}

// SegmentStore 把包持续写成定长轮转的 pcapng 段。
//
// 段在第一个真实包到来时才创建（起始时间取该包的时间），因此空包不会在磁盘上
// 留下任何段文件；每次封段都会追加一行索引并按保留策略清理最老的段。
type SegmentStore struct {
	mu     sync.Mutex
	opts   Options
	dir    string
	index  *os.File // 惰性打开、只追加
	sealed []SegmentInfo

	cur        *pcapng.Writer
	curFile    *os.File
	curName    string
	curNo      int64
	curStart   time.Time
	curEnd     time.Time
	curPackets int64

	closed bool
}

// Open 按 opts 准备目录并打开第一段（目录：<RootDir>/<CaptureID>/）。
//
// 目录在 Open 时创建；第一个段文件则延迟到第一个真实包写入时才创建，
// 这样"只写空包"的调用方不会在磁盘上产生任何多余内容。
func Open(opts Options) (*SegmentStore, error) {
	opts = normalizeOptions(opts)
	dir := filepath.Join(opts.RootDir, opts.CaptureID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("collect: mkdir %s: %w", dir, err)
	}
	return &SegmentStore{opts: opts, dir: dir}, nil
}

// normalizeOptions 补全默认值：空目录名、非正的段阈值视为使用默认值；
// 保留项里只有"正数"才表示限制，0/负数表示不限制。
func normalizeOptions(opts Options) Options {
	if opts.RootDir == "" {
		opts.RootDir = defaultRootDir
	}
	if opts.SegmentBytes <= 0 {
		opts.SegmentBytes = defaultSegmentBytes
	}
	if opts.LinkType < 0 {
		opts.LinkType = 0
	}
	if opts.RetentionBytes < 0 {
		opts.RetentionBytes = 0
	}
	if opts.RetentionHours < 0 {
		opts.RetentionHours = 0
	}
	return opts
}

// Write 写入一个包（热路径，每包调用）。
// p 为 nil 或 p.Data 为空 -> 直接返回 nil（不写、不报错）。
//
// 写完整个包之后才判断是否达到段大小阈值，因此绝不会把包拆到两个段里。
func (s *SegmentStore) Write(p *datamodel.Packet) error {
	if p == nil || len(p.Data) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("collect: Write on closed SegmentStore")
	}

	ts := p.Time
	if ts.IsZero() {
		ts = time.Now()
	}

	if s.cur == nil {
		if err := s.openSegment(ts); err != nil {
			return err
		}
	}

	if err := s.cur.WritePacket(p.Time, p.Data); err != nil {
		return fmt.Errorf("collect: write packet: %w", err)
	}
	s.curPackets++
	s.curEnd = ts

	if s.cur.BytesWritten() >= s.opts.SegmentBytes {
		if err := s.sealCurrent(); err != nil {
			return err
		}
		if err := s.enforceRetention(); err != nil {
			return err
		}
	}
	return nil
}

// Close 封掉当前段（写索引行 + 应用一次保留策略）。
func (s *SegmentStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	var firstErr error
	if err := s.sealCurrent(); err != nil {
		firstErr = err
	}
	if err := s.enforceRetention(); err != nil && firstErr == nil {
		firstErr = err
	}
	if s.index != nil {
		if err := s.index.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.index = nil
	}
	return firstErr
}

// Segments 返回已封段的索引（按段号升序；不含正在写的那一段）。
//
// 返回的是快照副本；已删除的段仍以 Deleted=true 的墓碑形式保留在结果里。
func (s *SegmentStore) Segments() []SegmentInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]SegmentInfo, len(s.sealed))
	copy(out, s.sealed)
	return out
}

// CurrentName 返回当前正在写的段文件名；没有则返回空串。
func (s *SegmentStore) CurrentName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.curName
}

// openSegment 创建下一个段文件并初始化其 pcapng 写入器。
// 调用方必须已持有 s.mu。
func (s *SegmentStore) openSegment(start time.Time) error {
	s.curNo++
	name := fmt.Sprintf("%s-%06d-%s.pcapng", s.opts.CaptureID, s.curNo, start.Format(segmentTimeLayout))
	path := filepath.Join(s.dir, name)

	f, err := os.Create(path)
	if err != nil {
		s.curNo--
		return fmt.Errorf("collect: create segment %s: %w", path, err)
	}
	w, err := pcapng.NewWriter(f, s.opts.LinkType, 0)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		s.curNo--
		return fmt.Errorf("collect: init pcapng writer for %s: %w", path, err)
	}

	s.cur = w
	s.curFile = f
	s.curName = name
	s.curStart = start
	s.curEnd = start
	s.curPackets = 0
	return nil
}

// sealCurrent 封掉当前段：冲刷并关闭文件、追加一行索引。
// 调用方必须已持有 s.mu。没有正在写的段时是空操作。
func (s *SegmentStore) sealCurrent() error {
	if s.cur == nil {
		return nil
	}

	info := SegmentInfo{
		No:        s.curNo,
		Name:      s.curName,
		Bytes:     s.cur.BytesWritten(),
		Packets:   s.curPackets,
		StartTime: s.curStart,
		EndTime:   s.curEnd,
	}

	flushErr := s.cur.Close() // 只 Flush，不关闭调用方的 io.Writer
	fileErr := s.curFile.Close()
	s.cur = nil
	s.curFile = nil
	s.curName = ""
	s.curPackets = 0

	if flushErr != nil {
		return fmt.Errorf("collect: flush segment %s: %w", info.Name, flushErr)
	}
	if fileErr != nil {
		return fmt.Errorf("collect: close segment %s: %w", info.Name, fileErr)
	}

	// 先记到内存、再追加索引，保证磁盘段文件与内存状态一致。
	s.sealed = append(s.sealed, info)
	if err := s.appendIndex(info); err != nil {
		return err
	}
	return nil
}

// ReadRange 返回时间落在 [from, to]（闭区间）内的原始帧，并报告本来源是否**完整覆盖**了该范围。
//
// complete 的含义：该范围内的数据在本来源里是齐全的
// （每个与 [from,to] 相交的段都存在且没被保留策略删掉）。有任何洞就返回 false。
//
// 实现要点：
//   - 只读 s.Segments() 的索引挑出与 [from,to] 相交的段，不依赖"正在写"状态
//     （store 已 Close 过也能正常读）；
//   - 先 Flush 当前正在写的段，并把它也一起读 —— 否则最新那一段永远缺失；
//   - 已删除（被保留策略删掉）的相交段 -> complete=false；
//   - 未删除的段文件缺失 / 解析失败 -> 返回错误。
func (s *SegmentStore) ReadRange(from, to time.Time) ([]Frame, bool, error) {
	// 在锁内取索引快照，并 Flush 当前段（只冲刷、不关闭底层文件），
	// 保证已写入的字节可被读到；随后立刻释放锁，逐段读文件不阻塞写路径。
	s.mu.Lock()
	segments := make([]SegmentInfo, len(s.sealed))
	copy(segments, s.sealed)
	if s.cur != nil {
		if err := s.cur.Flush(); err != nil {
			s.mu.Unlock()
			return nil, false, fmt.Errorf("collect: flush current segment: %w", err)
		}
		segments = append(segments, SegmentInfo{
			No:        s.curNo,
			Name:      s.curName,
			Bytes:     s.cur.BytesWritten(),
			Packets:   s.curPackets,
			StartTime: s.curStart,
			EndTime:   s.curEnd,
		})
	}
	dir := s.dir
	s.mu.Unlock()

	var (
		frames     []Frame
		intersects int
		complete   = true
	)
	for _, seg := range segments {
		// 与 [from,to] 相交：seg.EndTime >= from && seg.StartTime <= to。
		if seg.EndTime.Before(from) || seg.StartTime.After(to) {
			continue
		}
		intersects++
		if seg.Deleted {
			// 文件已被保留策略删除：范围内有洞，且无法再读回。
			complete = false
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, seg.Name))
		if err != nil {
			return nil, false, fmt.Errorf("collect: read segment %s: %w", seg.Name, err)
		}
		cap, err := pcapng.Parse(data, 0)
		if err != nil {
			return nil, false, fmt.Errorf("collect: parse segment %s: %w", seg.Name, err)
		}
		for _, p := range cap.Packets {
			if p == nil || p.Time.Before(from) || p.Time.After(to) {
				continue
			}
			d := make([]byte, len(p.Data))
			copy(d, p.Data)
			frames = append(frames, Frame{Time: p.Time, No: p.No, Data: d})
		}
	}
	// 没有任何段覆盖该范围时，无法证明完整，保守判为不完整。
	if intersects == 0 {
		complete = false
	}
	return frames, complete, nil
}
