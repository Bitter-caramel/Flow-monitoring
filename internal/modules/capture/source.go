package capture

import (
	"context"
	"time"
)

// Frame 一帧原始数据 + 元信息（解码前）。
type Frame struct {
	Data     []byte
	TS       time.Time
	LinkType int
}

// Source 数据源：回放与将来网卡抓包都实现这个接口。
// Next 返回 io.EOF 表示数据耗尽；其它 error 表示失败。
type Source interface {
	Next(ctx context.Context) (Frame, error)
	Describe() string
	Close() error
}
