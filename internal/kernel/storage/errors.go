package storage

import "errors"

// 本文件汇总 storage 包的错误哨兵值。
//
// 调用方优先用 errors.Is(err, ErrXxx) 判别，避免字符串匹配。

var (
	// ErrNotFound 记录不存在。
	ErrNotFound = errors.New("storage: record not found")

	// ErrConflict 唯一约束冲突（如重复 capture ID）。
	ErrConflict = errors.New("storage: conflict")

	// ErrClosed 存储已关闭。
	ErrClosed = errors.New("storage: closed")
)
