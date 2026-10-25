package plugin

import (
	"encoding/json"
	"fmt"
	"time"
)

// Void 是 net/rpc 方法的空返回值（占位）。
//
// net/rpc 要求每个方法都有 reply 指针；无返回数据的方法统一用 Void。
type Void struct{}

// Host 是宿主进程对模块进程暴露的服务接口（跨进程契约）。
//
// 模块进程在 Start 阶段通过 DialHost（读环境变量 FLOW_HOST_BRIDGE）回连宿主，
// 之后：
//   - Config：读配置快照
//   - Log：写宿主统一日志（保证所有模块日志汇聚一处）
//   - Publish/Poll：经宿主 eventbus 与其他模块解耦通信
//   - Capture*/Packet*：经宿主存储层读写元数据（模块不直连数据库）
//
// 设计依据：架构 v0.3 P2「契约第一」+ P3「一切可替换」；实施方案 2.0 §6.3
// 「跨进程事件经存储抽象」。
type Host interface {
	Config() ConfigSnapshot
	Log(level string, msg string)
	Publish(topic string, data []byte) error
	Poll(topic string, since uint64, max int) []EventRecord
	// RegisterHTTP 模块上报自己的 HTTP 监听地址（moduleID 用于模块退出时回收路由）。
	RegisterHTTP(httpBase, addr, moduleID string) error

	// —— 服务注册 / 注入（DSH 式 everything-is-a-plugin 的服务层）——
	// 提供者：RegisterService；消费者：LookupService。模块 Stop 时应 UnregisterService，
	// 宿主也会在模块进程退出时兜底回收（注册是可逆副作用，卸载即回滚）。
	RegisterService(ref ServiceRef) error
	LookupService(name string) (ServiceRef, bool)
	UnregisterService(name string) error

	// —— 存储（模块不直连数据库，经宿主访问）——
	// 模块侧用 internal/modules/common/hoststore 适配器把本组方法包装成
	// 完整的 storage.Storage，从而零改动复用既有存储实现代码。
	// 注意：原始抓包文件的读写由模块进程自己完成（local disk），
	// 宿主只负责元数据索引，避免大块字节走 RPC。
	CaptureCreate(rec CaptureRecord) error
	CaptureGet(id string) (CaptureRecord, bool)
	CaptureList(page Page) CapturePage
	CaptureDelete(id string) error

	PacketSaveBatch(captureID string, packets []PacketRecord) error
	PacketList(captureID string, page Page) PacketPage
	PacketCount(captureID string) int
	PacketDelete(captureID string) error
}

// RunRecord 是一个分析任务（Run）的持久化视图。
//
// 它是 Run 在存储层的稳定形态：字段与 capture 模块的 runView 对应，
// 用于服务重启后回填历史，避免"我分析过哪些证据包、结果如何"丢失。
type RunRecord struct {
	ID        string    `json:"id"`
	Mode      string    `json:"mode"`
	Source    string    `json:"source"`
	CaptureID string    `json:"capture_id,omitempty"`
	State     string    `json:"state"`
	Packets   int       `json:"packets"`
	Alerts    int       `json:"alerts"`
	Err       string    `json:"err,omitempty"`
	Started   time.Time `json:"started"`
	Finished  time.Time `json:"finished"`
}

// RunStore 是 Host 的**可选**扩展：宿主支持 Run 持久化时，模块可经类型断言使用。
//
// ★ 不并入 Host 接口，避免所有假 Host 测试桩都要跟着改：
//
//	if rs, ok := host.(plugin.RunStore); ok {
//	    _ = rs.RunSave(rec)
//	}
type RunStore interface {
	RunSave(rec RunRecord) error
	RunList(limit int) []RunRecord
}

// Section 把 ConfigSnapshot.Raw 里指定的顶层键解成 out。
//
// 键不存在或 Raw 为空时返回 nil（不视为错误），out 保持零值；
// JSON 非法或该键的值无法解成 out 时返回带上下文的错误。
//
// 典型用法（替代手写 json.Unmarshal([]byte(cfg.Raw), &root)）：
//
//	var settings detectSettings
//	if err := cfg.Section("detect", &settings); err != nil { ... }
func (c ConfigSnapshot) Section(key string, out any) error {
	if c.Raw == "" {
		return nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(c.Raw), &top); err != nil {
		return fmt.Errorf("plugin: 解析配置快照失败: %w", err)
	}
	raw, ok := top[key]
	if !ok {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("plugin: 解析配置段 %q 失败: %w", key, err)
	}
	return nil
}
