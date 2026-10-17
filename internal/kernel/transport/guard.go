package transport

import (
	"crypto/subtle"
	"net"
	"net/http"
	"net/url"
	"strings"

	"flow-monitoring/internal/kernel/modulecontrol"
)

// SetAPIToken 设置控制面 Token；空串 = 不启用 Token 鉴权。
//
// ★ 必须在 Server.Start 之前调用（装配期一次性注入，运行期不再变更）。
func (s *Server) SetAPIToken(token string) {
	s.apiToken = token
}

// guardMiddleware 是控制面三件套里的"CSRF + Token"两道门：
//
//   - Token：所有 /api/*（含 GET/HEAD）在配置了 token 时都要求
//     Authorization: Bearer <token>，不匹配 ⇒ 401 {"error":"unauthorized"}；
//   - CSRF：所有非 GET/HEAD 的 /api/* 必须带 X-Flow-Request: 1，
//     且若带 Origin，必须与自身来源（127.0.0.1/localhost/[::1] + 实际监听端口）
//     一致；否则 403。
//
// 这里不放宽为 CORS：不返回任何 Access-Control-Allow-* 头。
// 通过校验后把审计上下文（remote/auth/origin/request_id）注入请求 context，
// 供 modulecontrol 服务层写 logs/audit.jsonl。
func (s *Server) guardMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isAPIPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		if s.apiToken != "" && !requestHasValidToken(r, s.apiToken) {
			WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("X-Flow-Request") != "1" {
				WriteJSON(w, http.StatusForbidden, map[string]string{
					"error": "missing X-Flow-Request header",
				})
				return
			}
			if !s.originMatches(r) {
				WriteJSON(w, http.StatusForbidden, map[string]string{
					"error": "cross-origin request rejected",
				})
				return
			}
		}

		auth := "none"
		if s.apiToken != "" {
			auth = "token"
		}
		meta := modulecontrol.AuditMeta{
			Remote:    r.RemoteAddr,
			Auth:      auth,
			Origin:    r.Header.Get("Origin"),
			RequestID: RequestIDFrom(r.Context()),
		}
		ctx := modulecontrol.WithAuditMeta(r.Context(), meta)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// isAPIPath 判断请求是否落在控制面 API 前缀下。
func isAPIPath(path string) bool {
	return path == "/api" || strings.HasPrefix(path, "/api/")
}

// requestHasValidToken 校验 Authorization: Bearer <token>。
//
// 用 crypto/subtle.ConstantTimeCompare 比较，避免按字节短路。
func requestHasValidToken(r *http.Request, token string) bool {
	got, ok := bearerCredential(r.Header.Get("Authorization"))
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

// bearerCredential 解析 "Bearer xxx"（scheme 大小写不敏感）。
func bearerCredential(header string) (string, bool) {
	const prefix = "Bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	v := strings.TrimSpace(header[len(prefix):])
	return v, v != ""
}

// originMatches 校验 Origin（缺失视为同源请求放行）。
//
// 允许的来源固定为 http://127.0.0.1:<port>、http://localhost:<port>、
// http://[::1]:<port>，端口取实际监听端口（s.addr；测试里 addr 端口为 0 时
// 回退到请求 Host 的端口）。https / 其它主机一律拒绝。
func (s *Server) originMatches(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || !strings.EqualFold(u.Scheme, "http") {
		return false
	}
	switch strings.ToLower(u.Hostname()) {
	case "127.0.0.1", "localhost", "::1":
	default:
		return false
	}

	gotPort := u.Port()
	if gotPort == "" {
		gotPort = "80" // http 默认端口
	}
	wantPort := s.listenPort(r)
	return wantPort != "" && gotPort == wantPort
}

// listenPort 返回自身来源应使用的端口。
func (s *Server) listenPort(r *http.Request) string {
	if _, port, err := net.SplitHostPort(s.addr); err == nil {
		if port != "" && port != "0" {
			return port
		}
	}
	if _, port, err := net.SplitHostPort(r.Host); err == nil && port != "" {
		return port
	}
	return "80"
}
