// Package pluginhost 是宿主侧的插件宿主（L0 内核模块）。
//
// 职责：
//   - Bridge：实现 pkg/plugin.Host，把宿主的配置/日志/事件总线/存储
//     以 net/rpc 形式暴露给模块进程（模块不直连数据库/文件系统）
//   - Manager：经 hashicorp/go-plugin 启动模块进程、握手、拓扑启停、探活
//
// 设计依据：架构 v0.3 P2「契约第一」+ P3「一切可替换」；实施方案 2.0 §6.7
// 「进程级 gRPC 插件」——首版收敛为 net/rpc（无 protobuf 依赖），协议可换。
package pluginhost

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"flow-monitoring/internal/kernel/config"
	"flow-monitoring/internal/kernel/eventbus"
	"flow-monitoring/internal/kernel/logging"
	"flow-monitoring/internal/kernel/storage"
	"flow-monitoring/pkg/plugin"
)

// EventLog 进程内按主题维护的带序号事件环形缓冲。
//
// 模块进程通过 Host.Poll 拉取事件；EventLog 为每个主题维护单调递增 Seq，
// 模块用 since 游标做增量拉取（对应实施方案 2.0 第 5.3 节事件主题约定）。
type EventLog struct {
	mu   sync.Mutex
	seq  map[string]uint64
	ring map[string][]plugin.EventRecord
	cap  int
}

// NewEventLog 创建环形缓冲（cap 为每主题最大保留事件数）。
func NewEventLog(cap int) *EventLog {
	if cap <= 0 {
		cap = 1024
	}
	return &EventLog{
		seq:  make(map[string]uint64),
		ring: make(map[string][]plugin.EventRecord),
		cap:  cap,
	}
}

// Append 写入事件并分配 Seq（覆盖后修剪到 cap）。
func (l *EventLog) Append(ev plugin.EventRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ev.Seq = l.seq[ev.Topic] + 1
	l.seq[ev.Topic] = ev.Seq
	l.ring[ev.Topic] = append(l.ring[ev.Topic], ev)
	if n := len(l.ring[ev.Topic]); n > l.cap {
		l.ring[ev.Topic] = l.ring[ev.Topic][n-l.cap:]
	}
}

// Poll 返回 Seq > since 的事件，最多 max 条（按 Seq 升序）。
func (l *EventLog) Poll(topic string, since uint64, max int) []plugin.EventRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	if max <= 0 {
		max = 100
	}
	var out []plugin.EventRecord
	for _, ev := range l.ring[topic] {
		if ev.Seq > since {
			out = append(out, ev)
			if len(out) >= max {
				break
			}
		}
	}
	return out
}

// Bridge 实现 pkg/plugin.Host，宿主进程内服务模块进程。
//
// 持有内核服务引用；所有方法可在宿主进程内直接调用，
// 也可被 HostRPCServer（net/rpc）远程调用。
type Bridge struct {
	cfg    *config.Config
	logger *logging.Logger
	bus    *eventbus.Bus
	log    *EventLog

	// db 是运行期可替换的存储句柄（数据库断开/恢复时由 bootstrap 的
	// storageWatch 调 SetDB 更新）。
	//
	// ★ 为什么用 sync.RWMutex 而不是普通字段：本机 `go test -race` 不可用，
	// 而 SetDB（巡检 goroutine）与各存储方法（模块 RPC goroutine）会并发
	// 读写此字段，必须显式同步，不能靠"应该没事"。
	// ★ 为什么不用 atomic.Pointer：atomic.Pointer 只能存具体类型，存放
	// storage.Storage 接口需要额外包一层且读取时仍要判空；RWMutex 在这里
	// 更直观，也便于把"取快照"集中到 snapshotDB 一个入口。
	dbMu sync.RWMutex
	db   storage.Storage

	mu         sync.RWMutex
	routes     map[string]string            // HTTPBase -> 模块监听地址（网关反代用）
	routeOwner map[string]string            // HTTPBase -> 模块 ID（回收用）
	svcs       map[string]plugin.ServiceRef // 服务名 -> 服务引用（模块间注册/注入）
}

// NewBridge 创建宿主桥接服务。
func NewBridge(cfg *config.Config, logger *logging.Logger, bus *eventbus.Bus, db storage.Storage) *Bridge {
	return &Bridge{
		cfg:        cfg,
		logger:     logger,
		bus:        bus,
		db:         db,
		log:        NewEventLog(1024),
		routes:     make(map[string]string),
		routeOwner: make(map[string]string),
		svcs:       make(map[string]plugin.ServiceRef),
	}
}

// SetDB 运行期替换存储句柄。
//
// db == nil 表示存储不可用（数据库断开）；非 nil 表示已恢复（巡检
// Open+Migrate 成功后调用）。旧句柄由调用方（storageWatch）负责关闭，
// 本方法不 Close，避免与巡检/退出流程重复关闭。
func (b *Bridge) SetDB(db storage.Storage) {
	b.dbMu.Lock()
	b.db = db
	b.dbMu.Unlock()
}

// snapshotDB 返回当前存储句柄快照。
//
// ★ 所有读取 b.db 的地方都必须走这里：先用 RLock 取一次快照，后续操作
// 基于同一句柄，避免 setDB 在方法执行中途把 db 换掉/置空。
func (b *Bridge) snapshotDB() storage.Storage {
	b.dbMu.RLock()
	defer b.dbMu.RUnlock()
	return b.db
}

// Config 返回配置快照（模块进程读）。
func (b *Bridge) Config() plugin.ConfigSnapshot {
	raw, _ := json.Marshal(b.cfg)
	return plugin.ConfigSnapshot{
		DataDir:  b.cfg.DataDir,
		HTTPAddr: b.cfg.Server.HTTPAddr,
		Debug:    b.cfg.Server.Debug,
		Raw:      string(raw),
	}
}

// Log 模块日志汇聚到宿主统一日志。
func (b *Bridge) Log(level, msg string) {
	switch level {
	case "debug":
		b.logger.Debug(msg)
	case "warn":
		b.logger.Warn(msg)
	case "error":
		b.logger.Error(msg)
	default:
		b.logger.Info(msg)
	}
}

// Publish 事件写入 EventLog（供模块 Poll）+ 进程内总线（供 WS 推送）。
func (b *Bridge) Publish(topic string, data []byte) error {
	b.log.Append(plugin.EventRecord{Topic: topic, Data: data, Time: time.Now()})
	// 进程内订阅者（WS 推送）拿到原始 JSON 载荷
	return b.bus.Publish(topic, json.RawMessage(data))
}

// Poll 模块拉取事件。
func (b *Bridge) Poll(topic string, since uint64, max int) []plugin.EventRecord {
	return b.log.Poll(topic, since, max)
}

// RegisterHTTP 模块上报 HTTP 监听地址（网关反代 + 记录归属以便退出时回收）。
func (b *Bridge) RegisterHTTP(httpBase, addr, moduleID string) error {
	if httpBase == "" || addr == "" {
		return plugin.ErrMissingDependency
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.routes[httpBase] = addr
	b.routeOwner[httpBase] = moduleID
	return nil
}

// Route 查询某 HTTPBase 对应的模块地址（网关用）。
func (b *Bridge) Route(httpBase string) (string, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	addr, ok := b.routes[httpBase]
	return addr, ok
}

// Resolve 按最长前缀匹配请求路径对应的模块地址（网关用）。
func (b *Bridge) Resolve(path string) (string, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	best, bestAddr := "", ""
	for base, addr := range b.routes {
		if strings.HasPrefix(path, base) && len(base) > len(best) {
			best, bestAddr = base, addr
		}
	}
	return bestAddr, best != ""
}

// —— 服务注册 / 注入（DSH 式 everything-is-a-plugin 的服务层） ——

// RegisterService 注册一个模块提供的服务（可逆副作用：Stop/进程退出时回收）。
func (b *Bridge) RegisterService(ref plugin.ServiceRef) error {
	if ref.Name == "" {
		return plugin.ErrMissingDependency
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.svcs[ref.Name] = ref
	b.logger.Info("service registered", "name", ref.Name, "kind", ref.Kind,
		"endpoint", ref.Endpoint, "module", ref.ModuleID)
	return nil
}

// LookupService 查询服务引用（消费者 inject 用）。
func (b *Bridge) LookupService(name string) (plugin.ServiceRef, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	ref, ok := b.svcs[name]
	return ref, ok
}

// UnregisterService 注销服务（模块卸载时回滚）。
func (b *Bridge) UnregisterService(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.svcs, name)
	return nil
}

// UnregisterByModule 兜底回收某模块注册的全部服务与路由（进程异常退出时调用）。
func (b *Bridge) UnregisterByModule(moduleID string) {
	if moduleID == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for name, ref := range b.svcs {
		if ref.ModuleID == moduleID {
			delete(b.svcs, name)
		}
	}
	for base, owner := range b.routeOwner {
		if owner == moduleID {
			delete(b.routeOwner, base)
			delete(b.routes, base)
		}
	}
}

// Services 返回当前服务表快照（观测/健康检查用）。
func (b *Bridge) Services() map[string]plugin.ServiceRef {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make(map[string]plugin.ServiceRef, len(b.svcs))
	for k, v := range b.svcs {
		out[k] = v
	}
	return out
}

// ImportCapture 已移除：原始抓包文件由模块进程自己读写（本地磁盘），
// 宿主只负责元数据索引（CaptureCreate / PacketSaveBatch），避免大块字节走 RPC。

// CaptureCreate 写入抓包元数据索引（模块进程写盘后调用）。
func (b *Bridge) CaptureCreate(rec plugin.CaptureRecord) error {
	db := b.snapshotDB()
	if db == nil {
		return plugin.ErrStorageUnavailable
	}
	return db.Captures().Create(context.Background(), &rec)
}

// PacketSaveBatch 批量写入包元数据索引。
func (b *Bridge) PacketSaveBatch(captureID string, packets []plugin.PacketRecord) error {
	db := b.snapshotDB()
	if db == nil {
		return plugin.ErrStorageUnavailable
	}
	return db.Packets().SaveBatch(context.Background(), captureID, packets)
}

// CaptureGet 查询抓包元数据。
func (b *Bridge) CaptureGet(id string) (plugin.CaptureRecord, bool) {
	db := b.snapshotDB()
	if db == nil {
		return plugin.CaptureRecord{}, false
	}
	rec, err := db.Captures().Get(context.Background(), id)
	if err != nil {
		return plugin.CaptureRecord{}, false
	}
	return *rec, true
}

// CaptureList 分页列出抓包。
func (b *Bridge) CaptureList(page plugin.Page) plugin.CapturePage {
	db := b.snapshotDB()
	if db == nil {
		// ★ 不可用 ≠ 没有数据：Total 用 0 且 Err 明确写出原因，
		// 由 hoststore 转成 Go error，最终映射为 HTTP 503。
		return plugin.CapturePage{Total: 0, Err: plugin.ErrStorageUnavailable.Error()}
	}
	res, err := db.Captures().List(context.Background(), storage.Page{Offset: page.Offset, Limit: page.Limit})
	if err != nil {
		return plugin.CapturePage{Total: 0, Err: err.Error()}
	}
	return plugin.CapturePage{Items: res.Items, Total: res.Total}
}

// CaptureDelete 删除抓包。
func (b *Bridge) CaptureDelete(id string) error {
	db := b.snapshotDB()
	if db == nil {
		return plugin.ErrStorageUnavailable
	}
	return db.Captures().Delete(context.Background(), id)
}

// PacketList 分页列出数据包元数据。
func (b *Bridge) PacketList(captureID string, page plugin.Page) plugin.PacketPage {
	db := b.snapshotDB()
	if db == nil {
		return plugin.PacketPage{Total: 0, Err: plugin.ErrStorageUnavailable.Error()}
	}
	res, err := db.Packets().ListByCapture(context.Background(), captureID, storage.Page{Offset: page.Offset, Limit: page.Limit})
	if err != nil {
		return plugin.PacketPage{Total: 0, Err: err.Error()}
	}
	return plugin.PacketPage{Items: res.Items, Total: res.Total}
}

// PacketCount 统计某抓包的包数。
//
// 注意：Host 契约的 PacketCount 没有 error 返回值，不可用时只能返回 0；
// 调用方（query handler）先调 PacketList，后者会用 Err 明确报告不可用，
// 因此不会把"存储不可用"误判成"包里没有数据"。
func (b *Bridge) PacketCount(captureID string) int {
	db := b.snapshotDB()
	if db == nil {
		return 0
	}
	n, err := db.Packets().Count(context.Background(), captureID)
	if err != nil {
		return 0
	}
	return n
}

// PacketDelete 删除某抓包的全部包元数据。
func (b *Bridge) PacketDelete(captureID string) error {
	db := b.snapshotDB()
	if db == nil {
		return plugin.ErrStorageUnavailable
	}
	return db.Packets().DeleteByCapture(context.Background(), captureID)
}
