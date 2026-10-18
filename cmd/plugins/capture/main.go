// Command capture 是「采集 + 热路径 + 事件发布」模块的进程入口。
//
// 模块进程的标准结构（所有模块二进制同构）：
//  1. import 自己的模块包，拿到 plugin.Runtime；
//  2. 交给 plugin.ServeModule 暴露给宿主。
//
// 构建：go build -o bin/plugins/capture ./cmd/plugins/capture
// （或 go run ./cmd/fmbuild --modules=capture）
package main

import (
	"flow-monitoring/internal/modules/capture"
	"flow-monitoring/pkg/plugin"
)

func main() {
	plugin.ServeModule(&plugin.ModulePlugin{Impl: capture.Module()})
}
