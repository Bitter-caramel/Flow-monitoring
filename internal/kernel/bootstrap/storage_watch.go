package bootstrap

import (
	"context"
	"errors"
	"sync"
	"time"

	"flow-monitoring/internal/kernel/logging"
	"flow-monitoring/internal/kernel/storage"
	"flow-monitoring/internal/modules/store"
)

// 存储巡检的时间参数（用户指定：每 10 秒巡检一次，单次探测最多 3 秒）。
const (
	// StorageCheckInterval 是存储巡检周期（生产默认 10 秒）。
	StorageCheckInterval = 10 * time.Second
	// StorageCheckTimeout 是单次巡检（Open/Ping）的超时上限。
	StorageCheckTimeout = 3 * time.Second
)

// StorageStatus 是存储巡检的线程安全快照（对外观测用）。
//
// Since 只在状态翻转（可用 ⇄ 不可用）时更新，用于回答
// "当前这个状态已经持续了多久"。
type StorageStatus struct {
	Available bool      `json:"available"`
	Err       string    `json:"err,omitempty"`
	LastCheck time.Time `json:"last_check"`
	Since     time.Time `json:"since"` // 进入当前状态的时刻
}

// StorageHealth 是 /healthz 暴露的 storage 字段视图（StorageStatus + 巡检间隔）。
//
// 与 StorageStatus 的区别：Err 始终输出（空串表示可用），便于前端/运维
// 直接看到 "err": ""；并附带 interval_seconds 让巡检节奏可见。
type StorageHealth struct {
	Available       bool      `json:"available"`
	Err             string    `json:"err"`
	LastCheck       time.Time `json:"last_check"`
	Since           time.Time `json:"since"`
	IntervalSeconds int       `json:"interval_seconds"`
}

// storageProbe 是存储探测的可注入抽象。
//
// 真实实现（pgProbe）连 PostgreSQL；测试用假实现即可驱动状态机，
// 不必连真库。
type storageProbe interface {
	// Open 打开存储并完成 Migrate（建表幂等）。
	Open(ctx context.Context) (storage.Storage, error)
	// Ping 探测当前句柄是否仍可用。
	Ping(ctx context.Context, db storage.Storage) error
	// Close 关闭一个不再使用的句柄。
	Close(db storage.Storage)
}

// storageWatch 是存储巡检状态机。
//
// 状态流转：
//   - 不可用：每次 tick 尝试 Open；成功 ⇒ apply(db) + 可用 + 清空 Err；
//     失败 ⇒ 只更新 Err/LastCheck（错误文本变化时才打日志，避免刷屏）。
//   - 可用：每次 tick Ping；失败 ⇒ Close(db) + apply(nil) + 不可用。
//
// 状态翻转才更新 Since、才打 Info/Warn 日志；正常 tick 不打日志。
type storageWatch struct {
	probe    storageProbe
	apply    func(storage.Storage)
	logger   *logging.Logger
	interval time.Duration

	mu        sync.Mutex
	db        storage.Storage
	available bool
	lastErr   string
	lastCheck time.Time
	since     time.Time

	cancel  context.CancelFunc
	done    chan struct{}
	started bool
	stopped bool
	wg      sync.WaitGroup
}

// newStorageWatch 创建巡检器。生产默认 10 秒；测试可改 w.interval。
func newStorageWatch(probe storageProbe, apply func(storage.Storage), logger *logging.Logger) *storageWatch {
	now := time.Now()
	return &storageWatch{
		probe:     probe,
		apply:     apply,
		logger:    logger,
		interval:  StorageCheckInterval,
		lastCheck: now,
		since:     now,
	}
}

// seed 用 bootstrap 启动时已打开的句柄初始化状态。
//
// 这样巡检第一次 tick 走 Ping 分支，而不是把刚打开的句柄再 Open 一次
// （避免句柄泄漏与无谓的 "available again" 日志）。
func (w *storageWatch) seed(db storage.Storage) {
	if db == nil {
		return
	}
	now := time.Now()
	w.mu.Lock()
	w.db = db
	w.available = true
	w.lastErr = ""
	w.lastCheck = now
	w.since = now
	w.mu.Unlock()
}

// Start 启动巡检 goroutine：立即跑一次，此后每 interval 跑一次。
//
// ctx 是 bootstrap 的生命周期上下文；Stop 会取消内部子上下文并等待退出。
func (w *storageWatch) Start(ctx context.Context) {
	w.mu.Lock()
	if w.started || w.stopped {
		w.mu.Unlock()
		return
	}
	w.started = true
	loopCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.done = make(chan struct{})
	w.mu.Unlock()

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		defer close(w.done)

		// 立即跑一次：让启动瞬间的存储状态尽快落地。
		w.tick(loopCtx)

		t := time.NewTicker(w.interval)
		defer t.Stop()
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-t.C:
				w.tick(loopCtx)
			}
		}
	}()
}

// Stop 取消巡检并等待 goroutine 退出（幂等）。
func (w *storageWatch) Stop() {
	w.mu.Lock()
	if w.stopped {
		w.mu.Unlock()
		return
	}
	w.stopped = true
	cancel := w.cancel
	done := w.done
	w.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	w.wg.Wait()
}

// Status 返回当前状态快照（线程安全）。
func (w *storageWatch) Status() StorageStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	return StorageStatus{
		Available: w.available,
		Err:       w.lastErr,
		LastCheck: w.lastCheck,
		Since:     w.since,
	}
}

// HealthView 返回 /healthz 用的 storage 视图（含巡检间隔秒数）。
func (w *storageWatch) HealthView() StorageHealth {
	st := w.Status()
	return StorageHealth{
		Available:       st.Available,
		Err:             st.Err,
		LastCheck:       st.LastCheck,
		Since:           st.Since,
		IntervalSeconds: int(w.interval / time.Second),
	}
}

// currentDB 返回巡检持有的当前句柄（退出时用于关闭最新句柄）。
func (w *storageWatch) currentDB() storage.Storage {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.db
}

// tick 执行一次巡检。所有字段读写都受 w.mu 保护。
func (w *storageWatch) tick(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, StorageCheckTimeout)
	defer cancel()

	w.mu.Lock()
	available := w.available
	db := w.db
	w.mu.Unlock()

	if !available {
		w.recover(ctx)
		return
	}
	w.probePing(ctx, db)
}

// recover 在"不可用"状态下尝试重新打开存储。
func (w *storageWatch) recover(ctx context.Context) {
	newDB, err := w.probe.Open(ctx)
	now := time.Now()

	w.mu.Lock()
	w.lastCheck = now
	if err != nil {
		changed := err.Error() != w.lastErr
		w.lastErr = err.Error()
		w.mu.Unlock()
		// ★ 错误文本没变就保持安静：否则每 10 秒刷一条日志。
		if changed {
			w.logger.Warn("storage unavailable", "err", err)
		}
		return
	}
	w.db = newDB
	w.available = true
	w.lastErr = ""
	w.since = now
	w.mu.Unlock()

	if w.apply != nil {
		w.apply(newDB)
	}
	w.logger.Info("storage available again")
}

// probePing 在"可用"状态下探测句柄；失败则降级为不可用。
func (w *storageWatch) probePing(ctx context.Context, db storage.Storage) {
	err := w.probe.Ping(ctx, db)
	now := time.Now()

	if err == nil {
		w.mu.Lock()
		w.lastCheck = now
		w.mu.Unlock()
		return
	}

	// 先摘掉坏句柄：用旧句柄继续服务只会一直报错。
	w.probe.Close(db)

	w.mu.Lock()
	w.db = nil
	w.available = false
	w.lastErr = err.Error()
	w.lastCheck = now
	w.since = now
	w.mu.Unlock()

	if w.apply != nil {
		w.apply(nil)
	}
	w.logger.Warn("storage became unavailable", "err", err)
}

// pgProbe 是 storageProbe 的真实实现：连 PostgreSQL。
type pgProbe struct {
	dsn      string
	maxConns int
}

// Open 打开连接池并执行 Migrate（与 bootstrap 启动时的逻辑等价）。
func (p *pgProbe) Open(ctx context.Context) (storage.Storage, error) {
	pg, err := store.New(ctx, p.dsn, p.maxConns)
	if err != nil {
		return nil, err
	}
	if err := pg.Migrate(ctx); err != nil {
		_ = pg.Close()
		return nil, err
	}
	return pg, nil
}

// Ping 探测存储是否仍可用。
//
// storage.Storage 接口本身没有 Ping；PG 实现通过可选扩展
// storage.Pinger 暴露（internal/modules/store/postgres.go）。非 Pinger
// 实现无法探活，按可用处理（真实实现一定是 Pinger）。
func (p *pgProbe) Ping(ctx context.Context, db storage.Storage) error {
	if db == nil {
		return errors.New("storage: nil db")
	}
	pinger, ok := db.(storage.Pinger)
	if !ok {
		return nil
	}
	return pinger.Ping(ctx)
}

// Close 关闭一个不再使用的存储句柄。
func (p *pgProbe) Close(db storage.Storage) {
	if db != nil {
		_ = db.Close()
	}
}
