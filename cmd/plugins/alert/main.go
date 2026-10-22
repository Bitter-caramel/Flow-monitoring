// Command alert 是「告警消费」模块的进程入口。
//
// 模块进程的标准结构（所有模块二进制同构）：
//  1. import 自己的模块包，拿到 plugin.Runtime；
//  2. 交给 plugin.ServeModule 暴露给宿主。
//
// 本模块是"事件消费者样板"的第一个真实消费者：
//
//	Host.Poll(detect.feature) → pollsource → alert.Consumer → FileSink(JSONL)
//
// 构建：go build -o bin/plugins/alert ./cmd/plugins/alert
// （或 go run ./cmd/fmbuild --modules=alert）
package main

import (
	"flow-monitoring/internal/modules/alert"
	"flow-monitoring/pkg/plugin"
)

func main() {
	plugin.ServeModule(&plugin.ModulePlugin{Impl: alert.Module()})
}
