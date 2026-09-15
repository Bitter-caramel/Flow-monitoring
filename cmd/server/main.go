// Command server 是流量分析平台的主服务入口。
//
// 启动后拉起内核和所有功能模块，提供 HTTP/WebSocket 对外服务。
//
// 用法：
//
//	server [config.json]
//
// 不传配置文件时使用内置默认配置（开发期零配置可启动）。
// 关键配置可用环境变量覆盖：FLOW_DB_DSN / FLOW_HTTP_ADDR / FLOW_LOG_LEVEL / FLOW_DEBUG。
package main

import (
	"fmt"
	"os"

	"flow-monitoring/internal/kernel/bootstrap"
)

func main() {
	cfgPath := ""
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	if err := bootstrap.Run(cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "server: %v\n", err)
		os.Exit(1)
	}
}
