package transport

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"flow-monitoring/internal/kernel/logging"
)

// Server 对外 HTTP/WebSocket 服务。
//
// 封装 net/http.Server + 路由（http.ServeMux）+ 中间件链。
// 业务模块通过 Handle/HandleWS 注册路由；bootstrap 调用 Start 启动监听。
type Server struct {
	addr   string
	logger *logging.Logger
	server *http.Server
	mux    *http.ServeMux

	// handler 链：请求进入 → middleware(requestID) → middleware(accessLog) →
	// middleware(recover) → gateway（API 反代）→ mux（healthz/ws/静态）
	handler http.Handler

	// gateway API 网关（反代模块进程），由 bootstrap 注入路由解析器。
	gateway *gateway

	mu       sync.Mutex
	started  bool
	wsRoutes []wsRoute // 已注册的 WS 路由（优雅关闭时跟踪连接）
}

// wsRoute WebSocket 路由记录。
type wsRoute struct {
	pattern string
	hub     *WSHub
}

// New 创建 Server。
//
// addr 为监听地址（如 ":8080"）；logger 不能为 nil（否则 New 返回 nil）。
//
// 返回的 Server 尚未监听；调用 Start 后才对外服务。
func New(addr string, logger *logging.Logger) *Server {
	if logger == nil {
		return nil
	}
	mux := http.NewServeMux()
	s := &Server{
		addr:   addr,
		logger: logger,
		mux:    mux,
	}
	// 中间件链：requestID → accessLog → recover → gateway → mux
	s.gateway = newGateway(mux)
	s.handler = s.recoverMiddleware(s.accessLogMiddleware(s.requestIDMiddleware(s.gateway)))
	s.server = &http.Server{
		Addr:    addr,
		Handler: s.handler,
		// 防御性超时：v0.3 平台安全要求，避免慢速攻击耗尽连接
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return s
}

// Addr 返回监听地址。
func (s *Server) Addr() string { return s.addr }

// Handler 返回根 handler（测试用 / 嵌入到其他 server 用）。
func (s *Server) Handler() http.Handler { return s.handler }

// Mux 返回内部路由（业务模块直接在其上注册 REST 路由）。
//
// 业务模块注册示例：
//
//	s.Mux().HandleFunc("GET /api/v1/captures", listCaptures)
//	s.Mux().HandleFunc("POST /api/v1/captures", createCapture)
//	s.Mux().HandleFunc("GET /api/v1/captures/{id}", getCapture)
func (s *Server) Mux() *http.ServeMux { return s.mux }

// HandleFunc 便捷方法：注册 method+pattern 路由。
func (s *Server) HandleFunc(methodPattern string, fn http.HandlerFunc) {
	s.mux.HandleFunc(methodPattern, fn)
}

// SetGatewayResolver 注入 API 网关路由解析器（把模块 HTTPBase 反代到模块进程）。
//
// 由 bootstrap 调用，传入 pluginhost.Bridge.Resolve；不设置时网关透传。
func (s *Server) SetGatewayResolver(r RouteResolver) {
	s.gateway.setResolver(r)
}

// SetStaticDir 托管前端构建产物目录（如 frontend/dist）。
//
// 仅在目录非空时启用；API 与 WS 路由优先于静态文件。
func (s *Server) SetStaticDir(dir string) {
	if h := staticHandler(dir); h != nil {
		s.mux.Handle("/", h)
	}
}

// Start 阻塞监听；返回的错误仅来自 ListenAndServe（端口占用等）。
//
// 优雅关闭请配合 Shutdown 使用（bootstrap 在收到退出信号后调用）。
func (s *Server) Start() error {
	s.mu.Lock()
	s.started = true
	s.mu.Unlock()

	s.logger.Info("transport listening", "addr", s.addr)
	// ErrServerClosed 是正常关闭，不当作错误返回
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("transport: listen %s: %w", s.addr, err)
	}
	return nil
}

// Shutdown 优雅关闭（等待在途请求处理完成，超时后强制关闭）。
//
// 同时关闭所有 WebSocket hub（断开连接）。
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return nil
	}
	// 关闭所有 WS hub
	for _, r := range s.wsRoutes {
		r.hub.close()
	}
	s.mu.Unlock()

	s.logger.Info("transport shutting down")
	err := s.server.Shutdown(ctx)

	// 标记已停止（幂等关闭后 IsStarted 返回 false）
	s.mu.Lock()
	s.started = false
	s.mu.Unlock()

	return err
}

// IsStarted 是否已 Start。
func (s *Server) IsStarted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started
}

// WriteJSON 统一 JSON 响应（业务 handler 便捷使用）。
//
// RFC 7807 风格错误由各 handler 自行构造；这里只做通用编码。
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = encodeJSON(w, v)
}
