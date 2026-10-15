package collect

import (
	"sort"
	"sync"
	"time"

	"flow-monitoring/internal/kernel/datamodel"
)

const (
	// defaultRingBytes 是内存环形缓冲的默认字节上限（64MB）。
	defaultRingBytes = int64(64 << 20)
	// defaultRingWindow 是内存环形缓冲的默认保留窗口（10s）。
	defaultRingWindow = 10 * time.Second
)

// RingOptions 环形缓冲配置。
type RingOptions struct {
	MaxBytes int64         // 内存上限（默认 64<<20）；<=0 用默认值
	Window   time.Duration // 保留窗口（默认 10s）；<=0 用默认值
}

// Frame 是环里的一帧（Data 是**独立副本**）。
type Frame struct {
	Time time.Time
	No   int
	Data []byte
}

// Ring 在内存里保留"最近一段时间的原始帧"。并发安全。
//
// 它对应设计文档里的"快路"（内存环形缓冲）：零回读、不受磁盘轮转删除影响，
// 供证据提取直接取用。
//
// 帧只按**加入顺序**保存，多个并发生产者交错时**不保证**包时间全序
// （Add 的先后与包时间先后可能不一致）。因此：
//   - Slice 必须**全量扫描**，不能假定"后面的帧一定更晚"（否则会静默漏帧），
//     返回前再**按包时间排序**；
//   - 淘汰是**按到达顺序的近似淘汰**：可能多留几帧旧的，极端乱序下甚至先丢到
//     较新的帧——**这是可接受的**：本组件只是**缓存**，内存由 MaxBytes 严格
//     兜底、不会无界增长；"证据完整性"由**磁盘留存**负责（证据提取会回读段
//     文件补齐缺口）。
type Ring struct {
	mu       sync.Mutex
	maxBytes int64
	window   time.Duration

	frames []Frame   // 按加入顺序保存，不保证包时间全序
	bytes  int64     // frames 里 Data 的总字节数
	newest time.Time // 已加入帧里的最新包时间，用于推进时间窗

	// byConn 是「连接键 -> 该连接的帧」的内存索引（收包即分组）。
	// 每个列表按**加入顺序**追加；淘汰时必须与 frames 同步裁剪，否则索引会泄漏。
	byConn map[string][]Frame
	// keys 与 frames 一一对应，记录每帧的连接键（空串表示本帧未建索引），
	// 供淘汰时快速定位要从哪个连接列表里裁掉前缀。
	keys []string
}

// NewRing 创建环形缓冲。
func NewRing(opts RingOptions) *Ring {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = defaultRingBytes
	}
	if opts.Window <= 0 {
		opts.Window = defaultRingWindow
	}
	return &Ring{
		maxBytes: opts.MaxBytes,
		window:   opts.Window,
		byConn:   make(map[string][]Frame),
	}
}

// Add 放入一个包（热路径，每包调用）。
// p 为 nil 或 p.Data 为空 -> 直接返回（不报错、不占内存）。
// 帧数据会被**复制**进内部切片，绝不保存 p.Data 的切片/别名。
func (r *Ring) Add(p *datamodel.Packet) {
	if p == nil || len(p.Data) == 0 {
		return
	}

	// 先在锁外复制，既缩短持锁时间，也保证之后调用方改 p.Data 影响不到环。
	data := make([]byte, len(p.Data))
	copy(data, p.Data)

	// 连接键（收包即分组）。空串表示无端点信息，不建索引，避免脏键。
	key := datamodel.ConnKeyOf(p)

	r.mu.Lock()
	defer r.mu.Unlock()

	f := Frame{Time: p.Time, No: p.No, Data: data}
	r.frames = append(r.frames, f)
	r.keys = append(r.keys, key)
	r.bytes += int64(len(data))
	if p.Time.After(r.newest) {
		r.newest = p.Time
	}
	if key != "" {
		r.byConn[key] = append(r.byConn[key], f)
	}

	r.evictLocked()
}

// evictLocked 做两级淘汰。调用方必须已持有 r.mu。
//
// 注意：这里按**加入顺序**（而不是包时间顺序）从最老的一端近似淘汰。并发生产者
// 会让包时间乱序，所以这可能多留几帧旧的，极端情况下甚至先丢到较新的帧——
// **这是可接受的**：本组件是**缓存**，内存由 MaxBytes 严格兜底、不会无界增长；
// "证据完整性"由**磁盘留存**负责（证据提取会回读段文件补齐缺口）。
//
// ① 时间窗：丢弃早于「已知最新包时间 − Window」的帧；用**包时间**推进，
//
//	这样回放历史抓包也正确（不能依赖 time.Now()）。
//
// ② 字节上限：只要超过上限就从最老的继续丢，但至少保留最后 1 帧。
func (r *Ring) evictLocked() {
	// 时间窗淘汰：按加入顺序，从最老的一端数出要丢弃的前缀（近似淘汰）。
	cutoff := r.newest.Add(-r.window)
	drop := 0
	for drop < len(r.frames) && r.frames[drop].Time.Before(cutoff) {
		drop++
	}
	// 至少保留最后 1 帧，避免空环。包时间单调时最新帧永不早于 cutoff，
	// 这一保护不会触发；只有包时间乱序（如并发生产者交错）才需要兜底。
	if drop > len(r.frames)-1 {
		drop = len(r.frames) - 1
	}
	r.dropFrontLocked(drop)

	// 字节上限淘汰：至少保留最后 1 帧，避免空环。
	for r.bytes > r.maxBytes && len(r.frames) > 1 {
		r.dropFrontLocked(1)
	}
}

// dropFrontLocked 从最老的一端丢弃 n 帧并释放其数据引用。调用方必须已持有 r.mu。
//
// 必须**同步**把被丢的帧从 byConn 索引里删掉，否则索引会随运行时间无界泄漏。
// 做法：frames 与 keys 一一对应，且每个连接列表都按加入顺序追加；被丢弃的是
// frames 的一个**连续前缀**，因此它在每个连接列表里对应的也恰好是**前缀**——
// 逐帧把对应连接列表的队首裁掉即可。
func (r *Ring) dropFrontLocked(n int) {
	if n <= 0 {
		return
	}
	if n > len(r.frames) {
		n = len(r.frames)
	}
	for i := 0; i < n; i++ {
		r.bytes -= int64(len(r.frames[i].Data))
		r.dropConnHeadLocked(r.keys[i])
		r.frames[i] = Frame{} // 断开对底层 Data 的引用，便于被 GC
		r.keys[i] = ""
	}
	r.frames = r.frames[n:]
	r.keys = r.keys[n:]
}

// dropConnHeadLocked 从连接 key 的列表里裁掉队首一帧。调用方必须已持有 r.mu。
// key 为空或列表为空时什么都不做。
func (r *Ring) dropConnHeadLocked(key string) {
	if key == "" {
		return
	}
	lst := r.byConn[key]
	if len(lst) == 0 {
		return
	}
	lst[0] = Frame{} // 断开队首对底层 Data 的引用
	lst = lst[1:]
	if len(lst) == 0 {
		delete(r.byConn, key)
		return
	}
	r.byConn[key] = lst
}

// FramesByConn 返回该连接仍在 ring 内的全部帧，按时间先后排列；没有则返回 nil。
//
// 返回的是**独立副本**：切片与每帧 Data 都重新分配，调用方改动不会影响 ring 内部。
// r 为 nil 或 key 为空时返回 nil，不 panic。
func (r *Ring) FramesByConn(connKey string) []Frame {
	if r == nil || connKey == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	lst := r.byConn[connKey]
	if len(lst) == 0 {
		return nil
	}
	out := make([]Frame, len(lst))
	for i := range lst {
		data := make([]byte, len(lst[i].Data))
		copy(data, lst[i].Data)
		out[i] = Frame{Time: lst[i].Time, No: lst[i].No, Data: data}
	}
	// 按时间先后排列；时间相同则保持索引里的加入顺序（稳定排序）。
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Time.Before(out[j].Time)
	})
	return out
}

// ConnKeys 返回当前索引里出现过的全部连接键（用于观测/测试）。
// 返回的是独立切片，按字典序排序以保证确定性；r 为 nil 时返回 nil。
func (r *Ring) ConnKeys() []string {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.byConn) == 0 {
		return nil
	}
	out := make([]string, 0, len(r.byConn))
	for k := range r.byConn {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Slice 返回时间落在 [from, to]（闭区间）内的帧，按包时间升序。
// 返回的每个 Frame.Data 都是**独立副本**，调用方可以安全长期持有、随意修改。
//
// 帧只按加入顺序保存、不保证包时间全序，因此这里**全量扫描**、不能假定
// "后面的帧一定更晚"（否则会静默漏帧）；扫描后再按包时间**稳定排序**，
// 时间相同时保持加入顺序，保证输出确定性。
func (r *Ring) Slice(from, to time.Time) []Frame {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []Frame
	for i := range r.frames {
		f := &r.frames[i]
		if f.Time.Before(from) || f.Time.After(to) {
			continue
		}
		data := make([]byte, len(f.Data))
		copy(data, f.Data)
		out = append(out, Frame{Time: f.Time, No: f.No, Data: data})
	}
	// 返回前按包时间升序排序；时间相同则保持加入顺序（sort.SliceStable）。
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Time.Before(out[j].Time)
	})
	return out
}

// Frames 返回当前帧数（只用于观测/测试）。
func (r *Ring) Frames() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.frames)
}

// Bytes 返回当前占用字节数（只用于观测/测试）。
func (r *Ring) Bytes() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bytes
}
