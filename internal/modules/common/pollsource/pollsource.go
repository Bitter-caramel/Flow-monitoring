// Package pollsource 把宿主的事件拉取接口 plugin.Host.Poll 包装成一个
// 可读的 channel，供模块进程内的消费者（如 alert.Consumer）直接使用。
//
// 背景：模块进程订阅事件只有一条路——plugin.Host.Poll(topic, since, max)，
// 没有 push / subscribe 回调。宿主实现是"按主题维护的内存 ring + Seq 游标"，
// 因此本包负责：
//   - 用 since 游标循环增量拉取；
//   - 检测事件断层（ring 覆盖旧事件后 Seq 会跳号）并计数，不阻塞消费；
//   - 把 EventRecord 转成 eventbus.Event 投递到带缓冲 channel；
//   - channel 满时阻塞等待（背压），绝不丢弃——丢事件意味着下游漏告警。
package pollsource

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"flow-monitoring/internal/kernel/eventbus"
	"flow-monitoring/pkg/plugin"
)

const (
	// defaultBatch 是每轮最多拉取的事件数。
	defaultBatch = 100
	// defaultIdle 是没有新事件时的轮询间隔。
	defaultIdle = 200 * time.Millisecond
	// defaultBuffer 是投递 channel 的缓冲大小。
	defaultBuffer = 256
	// fromLatestMax 是"取当前最大 Seq"时传给 Poll 的 max。
	//
	// ★ 宿主实现是遍历 ring 后 append，不会按 max 预分配切片；这里给一个大值
	// 只是让一次调用覆盖整个 ring。调用方只取返回切片的最后一条，不复制、
	// 不预分配百万级内存。
	fromLatestMax = 1 << 20
)

// Options 是 Source 的配置。
type Options struct {
	// Batch 每轮最多拉多少条；<=0 用默认 100。
	Batch int
	// Idle 空闲轮询间隔；<=0 用默认 200ms。
	Idle time.Duration
	// FromLatest 为 true 时，启动时跳过历史，从当前最大 Seq 开始。
	FromLatest bool
}

// Stats 是 Source 的运行统计（快照）。
type Stats struct {
	Delivered uint64 // 已投递条数
	Gaps      uint64 // 检测到的断层次数
	Errors    uint64 // Poll 报错次数
	LastSeq   uint64 // 最后投递的 Seq
}

// Source 把 Host.Poll 变成一个事件 channel。
//
// 使用方式：
//
//	src := pollsource.New(host, "detect.feature", pollsource.Options{})
//	defer src.Close()
//	cons := alert.NewConsumer(src.C(), sink, alert.ConsumerOptions{})
//
// ★ Source 拥有 channel：Close 后循环退出并关闭 C()，消费端可以正常收尾。
type Source struct {
	host  plugin.Host
	topic string
	batch int
	idle  time.Duration

	// initialSince 是循环的起点。FromLatest 时在 New 内同步算出，
	// 保证"构造后新产生的事件"与"构造前的历史"边界确定。
	initialSince uint64

	ch chan eventbus.Event

	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup

	delivered atomic.Uint64
	gaps      atomic.Uint64
	errors    atomic.Uint64
	lastSeq   atomic.Uint64
}

// New 创建并启动 Source。
//
// FromLatest 的"当前最大 Seq"在 New 内同步探测一次，这样"构造完成"就是
// 历史/新事件的确定分界，不会与后台循环抢跑。
func New(host plugin.Host, topic string, opts Options) *Source {
	if opts.Batch <= 0 {
		opts.Batch = defaultBatch
	}
	if opts.Idle <= 0 {
		opts.Idle = defaultIdle
	}
	s := &Source{
		host:  host,
		topic: topic,
		batch: opts.Batch,
		idle:  opts.Idle,
		ch:    make(chan eventbus.Event, defaultBuffer),
		done:  make(chan struct{}),
	}
	if opts.FromLatest {
		s.initialSince = s.latestSeq()
	}
	s.wg.Add(1)
	go s.loop()
	return s
}

// C 返回事件 channel。Source.Close 后该 channel 被关闭。
func (s *Source) C() <-chan eventbus.Event { return s.ch }

// Stats 返回当前统计快照。
func (s *Source) Stats() Stats {
	return Stats{
		Delivered: s.delivered.Load(),
		Gaps:      s.gaps.Load(),
		Errors:    s.errors.Load(),
		LastSeq:   s.lastSeq.Load(),
	}
}

// Close 停止轮询、等待循环退出并关闭 channel（幂等）。
//
// ★ 关闭后的 channel 仍会先被消费端读完缓冲，因此不会丢已投递事件。
func (s *Source) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.wg.Wait()
	})
}

// loop 是拉取循环：Poll → 逐条投递 → since = 最后一条.Seq → 无事件则等待。
func (s *Source) loop() {
	defer s.wg.Done()
	defer close(s.ch)

	since := s.initialSince
	for {
		select {
		case <-s.done:
			return
		default:
		}

		evs := s.poll(since)
		if len(evs) == 0 {
			if !s.waitIdle() {
				return
			}
			continue
		}

		// 逐条投递，并在每次推进游标时检查断层。
		//
		// ★ 断层检测：since 过旧时宿主返回的第一条 Seq 会跳号（ring 覆盖旧事件）。
		// 允许继续消费（不阻塞），但必须计数并写 warn 日志。
		// 同时检查批内相邻两条的跳号——宿主一次可能返回"跳号前 + 跳号后"两条，
		// 只看首条会漏计。
		for _, rec := range evs {
			if rec.Seq > since+1 {
				s.gaps.Add(1)
				s.logf("warn", fmt.Sprintf(
					"pollsource: %s 事件断层：期望 Seq %d，实际 %d（跳过 %d..%d）",
					s.topic, since+1, rec.Seq, since+1, rec.Seq-1))
			}

			ev := eventbus.Event{
				Topic:   rec.Topic,
				Payload: rec.Data,
				TraceID: rec.TraceID,
				Time:    rec.Time,
			}
			// 满时阻塞（背压），但不丢；Close 时优先退出避免卡死。
			select {
			case s.ch <- ev:
			case <-s.done:
				return
			}
			since = rec.Seq
			s.delivered.Add(1)
			s.lastSeq.Store(rec.Seq)
		}
	}
}

// poll 用本轮的 Batch 大小调用宿主 Poll。
func (s *Source) poll(since uint64) []plugin.EventRecord {
	return s.pollWithMax(since, s.batch)
}

// pollWithMax 调用宿主 Poll，并用 recover 与计数兜住任何意外。
//
// 契约里 Poll 不返回 error，Errors 为未来的实现与"宿主桥异常"留出可观测口径。
func (s *Source) pollWithMax(since uint64, max int) (out []plugin.EventRecord) {
	if s.host == nil {
		s.errors.Add(1)
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			s.errors.Add(1)
			s.logf("error", fmt.Sprintf("pollsource: %s Poll panic: %v", s.topic, r))
			out = nil
		}
	}()
	return s.host.Poll(s.topic, since, max)
}

// latestSeq 探测主题当前最大 Seq；拿不到返回 0（从头部开始消费）。
//
// ★ 只取返回切片的最后一条，不复制整个 ring，也不按 max 预分配。
func (s *Source) latestSeq() uint64 {
	evs := s.pollWithMax(0, fromLatestMax)
	if len(evs) == 0 {
		return 0
	}
	return evs[len(evs)-1].Seq
}

// waitIdle 等待一个空闲间隔；Close 时立即返回 false。
func (s *Source) waitIdle() bool {
	t := time.NewTimer(s.idle)
	defer t.Stop()
	select {
	case <-s.done:
		return false
	case <-t.C:
		return true
	}
}

// logf 写宿主日志（host 为空时静默）。
func (s *Source) logf(level, msg string) {
	if s.host != nil {
		s.host.Log(level, msg)
	}
}
