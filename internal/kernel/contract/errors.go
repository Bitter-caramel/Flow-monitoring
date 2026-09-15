package contract

import "errors"

// 本文件汇总 contract 包的错误哨兵值。
//
// 调用方优先用 errors.Is(err, ErrXxx) 判别，避免字符串匹配。

var (
	// ErrConflict 契约 ID 冲突：两个模块声称实现同一契约。
	ErrConflict = errors.New("contract: id conflict")

	// ErrInvalidContract 契约或其实现为 nil。
	ErrInvalidContract = errors.New("contract: invalid contract (nil or nil impl)")

	// ErrNotFound 查询的契约未注册。
	ErrNotFound = errors.New("contract: not found")

	// ErrCapabilityNotFound 契约未声明该 capability。
	ErrCapabilityNotFound = errors.New("contract: capability not found")

	// ErrVersionIncompatible 调用方期望版本与实现版本不兼容。
	ErrVersionIncompatible = errors.New("contract: version incompatible")
)
