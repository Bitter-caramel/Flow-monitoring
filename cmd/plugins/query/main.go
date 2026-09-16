// Command query 是「查询服务」模块的进程入口。
//
// 模块进程的标准结构（所有模块二进制同构）：
//  1. import 自己的模块包，拿到 plugin.Runtime；
//  2. 交给 plugin.ServeModule 暴露给宿主。
//
// 进程启动参数（宿主注入）：
//   - 环境变量 FLOW_HOST_BRIDGE：宿主桥接地址，Runtime 内部据此回连宿主。
//
// 构建：go build -o bin/plugins/query ./cmd/plugins/query
// （或一键 scripts/build-plugins.sh）
package main

import (
	"flow-monitoring/internal/modules/query"
	"flow-monitoring/pkg/plugin"
)

func main() {
	plugin.ServeModule(&plugin.ModulePlugin{Impl: query.Module()})
}
