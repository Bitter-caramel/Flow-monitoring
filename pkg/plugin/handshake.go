package plugin

import hplugin "github.com/hashicorp/go-plugin"

// Handshake 宿主与模块进程之间的握手协议。
//
// 双方必须使用完全一致的 MagicCookie，否则 go-plugin 会在启动时拒绝连接，
// 防止把非本平台的进程误当插件加载（供应链安全）。
var Handshake = hplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "FLOW_MONITORING_PLUGIN",
	MagicCookieValue: "flow-monitoring-v1",
}

// Protocol 本平台插件采用的传输协议：net/rpc（无 protobuf 依赖，跨平台）。
// go-plugin 同时支持 gRPC，但 gRPC 需要 protoc 代码生成，故首版收敛为 net/rpc。
const Protocol = hplugin.ProtocolNetRPC

// AllowedProtocols 宿主加载插件时允许的协议白名单。
var AllowedProtocols = []hplugin.Protocol{Protocol}
