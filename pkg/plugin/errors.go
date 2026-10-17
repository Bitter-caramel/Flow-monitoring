package plugin

import "errors"

// 插件 SDK 的错误哨兵值。
//
// 这些错误会跨进程传播（net/rpc 序列化 error 时只保留字符串），
// 因此宿主侧用 errors.Is 判断时应依赖本包定义的哨兵，而不是具体实现。
var (
	// ErrMissingDependency 模块依赖的服务缺失。
	ErrMissingDependency = errors.New("plugin: missing dependency")

	// ErrNotRunning 模块尚未 Start 却调用了需要运行态的方法。
	ErrNotRunning = errors.New("plugin: not running")

	// ErrNotFound 资源不存在。
	ErrNotFound = errors.New("plugin: not found")

	// ErrConflict 资源冲突（重复 ID 等）。
	ErrConflict = errors.New("plugin: conflict")

	// ErrStorageUnavailable 存储层不可用（数据库未连接）。
	//
	// ★ 与 ErrNotRunning 严格区分：后者表示"模块还没 Start"，本错误表示
	// "模块已运行，但宿主存储（数据库）当前不可用"。把后者报成前者会把
	// 用户和运维引向错误方向（以为模块没开启），这是项目红线。
	ErrStorageUnavailable = errors.New("storage unavailable: database not connected")
)
