// situation 模块进程入口：态势评估引擎。
//
// 与其它插件一致：只做 ServeModule，业务逻辑全在 internal/modules/situation。
package main

import (
	"flow-monitoring/internal/modules/situation"
	"flow-monitoring/pkg/plugin"
)

func main() {
	plugin.ServeModule(&plugin.ModulePlugin{Impl: situation.Module()})
}
