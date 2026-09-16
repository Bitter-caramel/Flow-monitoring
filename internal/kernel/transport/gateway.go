package transport

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// RouteResolver 网关路由解析器：给定请求路径，返回要反代的模块地址。
//
// 由 pluginhost.Bridge 实现：按最长前缀匹配已注册的模块 HTTPBase。
type RouteResolver func(path string) (addr string, ok bool)

// gateway 是 API 网关：把匹配模块 HTTPBase 前缀的请求反代到对应模块进程。
//
// 设计依据：模块进程各自监听独立端口、对外只暴露路由前缀（Manifest.HTTPBase），
// 宿主 transport 统一反代，浏览器侧无需感知模块进程拓扑（微服务网关模式）。
type gateway struct {
	resolver RouteResolver
	next     http.Handler
}

// newGateway 创建网关；resolver 为 nil 时全部透传。
func newGateway(next http.Handler) *gateway {
	return &gateway{next: next}
}

// setResolver 注入路由解析器。
func (g *gateway) setResolver(r RouteResolver) { g.resolver = r }

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if g.resolver != nil {
		if addr, ok := g.resolver(r.URL.Path); ok {
			g.proxy(addr, w, r)
			return
		}
	}
	g.next.ServeHTTP(w, r)
}

// proxy 反代到模块进程地址（保留原始路径与查询串）。
func (g *gateway) proxy(addr string, w http.ResponseWriter, r *http.Request) {
	target, err := url.Parse("http://" + addr)
	if err != nil {
		WriteJSON(w, http.StatusBadGateway, map[string]string{"error": "bad gateway target"})
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ServeHTTP(w, r)
}

// staticHandler 静态文件托管（前端构建产物 dist）。
func staticHandler(dir string) http.Handler {
	if dir == "" {
		return nil
	}
	fs := http.FileServer(http.Dir(dir))
	// SPA 回退：非文件路径回退到 index.html
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/healthz" {
			http.NotFound(w, r)
			return
		}
		fs.ServeHTTP(w, r)
	})
}
