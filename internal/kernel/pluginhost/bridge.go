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
	db     storage.Storage
	log    *EventLog

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

// ImportCapture 已移除：原始 pcap 文件由模块进程自己读写（本地磁盘），
// 宿主只负责元数据索引（CaptureCreate / PacketSaveBatch），避免大块字节走 RPC。

// CaptureCreate 写入抓包元数据索引（模块进程写盘后调用）。
func (b *Bridge) CaptureCreate(rec plugin.CaptureRecord) error {
	if b.db == nil {
		return plugin.ErrNotRunning
	}
	return b.db.Captures().Create(context.Background(), &rec)
}

// PacketSaveBatch 批量写入包元数据索引。
func (b *Bridge) PacketSaveBatch(captureID string, packets []plugin.PacketRecord) error {
	if b.db == nil {
		return plugin.ErrNotRunning
	}
	return b.db.Packets().SaveBatch(context.Background(), captureID, packets)
}

// CaptureGet 查询抓包元数据。
func (b *Bridge) CaptureGet(id string) (plugin.CaptureRecord, bool) {
	if b.db == nil {
		return plugin.CaptureRecord{}, false
	}
	rec, err := b.db.Captures().Get(context.Background(), id)
	if err != nil {
		return plugin.CaptureRecord{}, false
	}
	return *rec, true
}

// CaptureList 分页列出抓包。
func (b *Bridge) CaptureList(page plugin.Page) plugin.CapturePage {
	if b.db == nil {
		return plugin.CapturePage{Total: -1}
	}
	res, err := b.db.Captures().List(context.Background(), storage.Page{Offset: page.Offset, Limit: page.Limit})
	if err != nil {
		return plugin.CapturePage{Total: -1}
	}
	return plugin.CapturePage{Items: res.Items, Total: res.Total}
}

// CaptureDelete 删除抓包。
func (b *Bridge) CaptureDelete(id string) error {
	if b.db == nil {
		return plugin.ErrNotRunning
	}
	return b.db.Captures().Delete(context.Background(), id)
}

// PacketList 分页列出数据包元数据。
func (b *Bridge) PacketList(captureID string, page plugin.Page) plugin.PacketPage {
	if b.db == nil {
		return plugin.PacketPage{Total: -1}
	}
	res, err := b.db.Packets().ListByCapture(context.Background(), captureID, storage.Page{Offset: page.Offset, Limit: page.Limit})
	if err != nil {
		return plugin.PacketPage{Total: -1}
	}
	return plugin.PacketPage{Items: res.Items, Total: res.Total}
}

// PacketCount 统计某抓包的包数。
func (b *Bridge) PacketCount(captureID string) int {
	if b.db == nil {
		return 0
	}
	n, err := b.db.Packets().Count(context.Background(), captureID)
	if err != nil {
		return 0
	}
	return n
}

// PacketDelete 删除某抓包的全部包元数据。
func (b *Bridge) PacketDelete(captureID string) error {
	if b.db == nil {
		return plugin.ErrNotRunning
	}
	return b.db.Packets().DeleteByCapture(context.Background(), captureID)
}
