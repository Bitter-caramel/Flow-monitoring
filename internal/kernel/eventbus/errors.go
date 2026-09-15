package eventbus

import "errors"

// 本文件汇总 eventbus 包的错误哨兵值。

var (
	// ErrClosed 总线已关闭，禁止发布。
	ErrClosed = errors.New("eventbus: bus closed")

	// ErrInvalidTopic 主题为空。
	ErrInvalidTopic = errors.New("eventbus: invalid topic (empty)")
)
