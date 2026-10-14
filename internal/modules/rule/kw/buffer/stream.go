package buffer

import (
	"flow-monitoring/internal/modules/rule"
	"flow-monitoring/internal/modules/rule/kw"
)

// streamBufKW 注册 "stream" 缓冲关键字（P1：TCP 重组后的流）。
//
// 说明：本目录现有缓冲（payload / http_uri / dns_query / ...）集中写在
// buffers.go 的 bufTable 里，再由该文件唯一的 init 循环统一注册。
// 本步按「新增一个文件」的要求新增本文件，复用同一套 bufKW 机制注册同名
// 缓冲区 "stream"；直接调用 kw.Register，不受跨文件 init 顺序影响。
func init() {
	kw.Register(bufKW{name: "stream", buf: rule.Buffer("stream")})
}
