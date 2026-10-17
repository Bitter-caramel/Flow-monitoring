package config

import (
	"fmt"
	"net"
	"strings"
)

// ValidateListenAuth 做启动期"监听地址 + Token"的硬校验：
//
//   - Token 非空：通过（非回环监听已具备鉴权能力）；
//   - Token 为空且监听地址是回环（127.0.0.1 / localhost / ::1 / 空主机）：通过；
//   - Token 为空且监听地址不是回环（如 0.0.0.0、::、局域网 IP）：拒绝启动。
//
// 空主机（":18080"）等价于监听所有网卡，但按设计文档 §6.3 的约定
// （127.0.0.1/localhost/::1/空 属于允许清单）视为回环，保持零配置开发可用。
//
// 这是一个纯函数：不读文件、不读环境变量，便于单元测试。
func ValidateListenAuth(addr, token string) error {
	if strings.TrimSpace(token) != "" {
		return nil
	}
	if IsLoopbackListenAddr(addr) {
		return nil
	}
	return fmt.Errorf("非回环监听必须配置 auth.token 或 FLOW_API_TOKEN（当前监听 %q）", addr)
}

// IsLoopbackListenAddr 判断监听地址是否属于回环/空主机。
//
// 支持 "127.0.0.1:18080"、"localhost:18080"、"[::1]:18080"、":18080"、
// 以及不带端口的 "127.0.0.1"、"localhost"、"::1"。无法可靠判定时按
// "非回环"处理（安全侧默认拒绝）。
func IsLoopbackListenAddr(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return true
	}

	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	} else if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
	} else if strings.Count(addr, ":") == 1 {
		// 形如 "localhost:18080" 时 SplitHostPort 已成功；走到这里说明
		// 是 "::1" 这类裸 IPv6，保留整个 addr 交给 ParseIP 判定。
		host = addr
	}

	host = strings.TrimSpace(host)
	if host == "" {
		return true
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	// 去掉 IPv6 zone（如 fe80::1%lo0），只按地址本身判定。
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
