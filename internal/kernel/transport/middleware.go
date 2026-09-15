package transport

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"runtime/debug"
	"time"
)

// requestIDMiddleware 为每个请求注入唯一 request_id。
//
// 对应实施方案 2.0 第 5.3 节"事件统一携带 trace_id"的 HTTP 层落地。
// request_id 追加到响应头 X-Request-ID，并存入请求 context，供下游 handler 读取。
func (s *Server) requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		ctx := withRequestID(r.Context(), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// accessLogMiddleware 记录每个请求的访问日志（方法/路径/状态码/耗时）。
func (s *Server) accessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		s.logger.Info("http access",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
			"request_id", RequestIDFrom(r.Context()),
		)
	})
}

// recoverMiddleware panic 恢复：单个请求 panic 不拖垮整个服务。
//
// 对应"单个畸形请求不能中断服务"的防御思想。
func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("http panic recovered",
					"panic", rec,
					"stack", string(debug.Stack()),
					"path", r.URL.Path,
					"request_id", RequestIDFrom(r.Context()),
				)
				WriteJSON(w, http.StatusInternalServerError, map[string]string{
					"error": "internal server error",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// statusRecorder 包装 ResponseWriter 捕获状态码，并透传 Hijacker/Flusher
// 接口，保证 WebSocket 升级等需要底层连接的操作正常工作。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Hijack 透传底层连接（WebSocket 升级依赖）。
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := r.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Flush 透传（SSE/流式响应依赖）。
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// newRequestID 生成 16 字节随机 hex 作为请求 ID。
func newRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
