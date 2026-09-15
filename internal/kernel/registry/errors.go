package registry

import "errors"

// 本文件汇总 registry 包的错误哨兵值。

var (
	// ErrInvalidPlugin 插件为空或 ID 为空。
	ErrInvalidPlugin = errors.New("registry: invalid plugin (nil or empty ID)")

	// ErrConflict 插件 ID 冲突：两个插件争抢同一 ID。
	ErrConflict = errors.New("registry: plugin id conflict")

	// ErrUnresolvedDep 插件依赖了未注册的插件。
	ErrUnresolvedDep = errors.New("registry: unresolved dependency")

	// ErrCyclicDependency 检测到循环依赖，无法拓扑排序。
	ErrCyclicDependency = errors.New("registry: cyclic dependency detected")
)
