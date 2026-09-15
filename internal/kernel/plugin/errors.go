package plugin

import "errors"

// 本文件汇总 plugin 包的错误哨兵值。

var (
	// ErrMissingDependency 插件所需的依赖服务缺失。
	ErrMissingDependency = func(name string) error {
		return errors.New("plugin: missing dependency: " + name)
	}

	// ErrMount Mount 阶段失败。
	ErrMount = func(msg string) error {
		return errors.New("plugin: mount failed: " + msg)
	}

	// ErrNotMounted 在未 Mount 时调用了 Start/Stop。
	ErrNotMounted = errors.New("plugin: not mounted")
)
