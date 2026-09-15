package registry

import "errors"

// 本文件汇总 registry 包的错误哨兵值。
//
// 调用方优先用 errors.Is(err, ErrXxx) 判别，避免字符串匹配。

var (
	// ErrInvalidModule 模块或其 ID 为空。
	ErrInvalidModule = errors.New("registry: invalid module (nil or empty ID)")

	// ErrConflict 模块 ID 冲突：两个模块争抢同一 ID。
	ErrConflict = errors.New("registry: module id conflict")

	// ErrUnresolvedDep 模块依赖了未注册的模块。
	ErrUnresolvedDep = errors.New("registry: unresolved dependency")

	// ErrCyclicDependency 检测到循环依赖，无法拓扑排序。
	ErrCyclicDependency = errors.New("registry: cyclic dependency detected")
)
