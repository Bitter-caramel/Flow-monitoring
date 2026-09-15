package transport

import (
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WSConn WebSocket 连接封装。
//
// 包装 *websocket.Conn，提供带写锁的安全发送。
// 业务模块通过 WSHub 获取连接并 Send 消息。
type WSConn struct {
	conn *websocket.Conn
	mu   sync.Mutex // 写锁：防止并发写同一连接导致协议错乱
}

// Send 发送文本消息（并发安全）。
func (c *WSConn) Send(msg []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteMessage(websocket.TextMessage, msg)
}

// SendJSON 发送 JSON 消息（并发安全）。
func (c *WSConn) SendJSON(v any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteJSON(v)
}

// Close 关闭连接。
func (c *WSConn) Close() error { return c.conn.Close() }

// RemoteAddr 远端地址（观测/日志用）。
func (c *WSConn) RemoteAddr() string { return c.conn.RemoteAddr().String() }

// WSHub WebSocket 连接集线器。
//
// 管理某一路由上的所有活跃连接，支持广播与优雅关闭。
// 对应 v0.3 第 6.9 节"动态告警/处置/采集健康：WebSocket 推送"的最小实现。
type WSHub struct {
	mu    sync.RWMutex
	conns map[*WSConn]struct{}

	onConnect func(*WSConn)
	onMessage func(*WSConn, []byte)
	onClose   func(*WSConn)
}

// newWSHub 创建 hub（内部使用，业务模块通过 Server.HandleWS 获取）。
func newWSHub() *WSHub {
	return &WSHub{conns: make(map[*WSConn]struct{})}
}

// SetOnConnect 设置连接建立回调（可选）。
func (h *WSHub) SetOnConnect(fn func(*WSConn)) { h.onConnect = fn }

// SetOnMessage 设置消息回调（可选；默认丢弃收到的消息）。
func (h *WSHub) SetOnMessage(fn func(*WSConn, []byte)) { h.onMessage = fn }

// SetOnClose 设置连接关闭回调（可选）。
func (h *WSHub) SetOnClose(fn func(*WSConn)) { h.onClose = fn }

// Broadcast 向所有活跃连接广播文本消息。
//
// 单个连接发送失败仅跳过（连接随后由读循环检测关闭并注销），不影响其他连接。
func (h *WSHub) Broadcast(msg []byte) {
	h.mu.RLock()
	conns := make([]*WSConn, 0, len(h.conns))
	for c := range h.conns {
		conns = append(conns, c)
	}
	h.mu.RUnlock()

	for _, c := range conns {
		_ = c.Send(msg)
	}
}

// BroadcastJSON 向所有连接广播 JSON 消息。
func (h *WSHub) BroadcastJSON(v any) {
	h.mu.RLock()
	conns := make([]*WSConn, 0, len(h.conns))
	for c := range h.conns {
		conns = append(conns, c)
	}
	h.mu.RUnlock()

	for _, c := range conns {
		_ = c.SendJSON(v)
	}
}

// Count 当前活跃连接数（观测/健康检查用）。
func (h *WSHub) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.conns)
}

// register 注册连接（内部使用）。
func (h *WSHub) register(c *WSConn) {
	h.mu.Lock()
	h.conns[c] = struct{}{}
	h.mu.Unlock()
	if h.onConnect != nil {
		h.onConnect(c)
	}
}

// unregister 注销连接（内部使用）。
func (h *WSHub) unregister(c *WSConn) {
	h.mu.Lock()
	if _, ok := h.conns[c]; ok {
		delete(h.conns, c)
		h.mu.Unlock()
		if h.onClose != nil {
			h.onClose(c)
		}
		return
	}
	h.mu.Unlock()
}

// close 关闭所有连接（Server.Shutdown 时调用）。
func (h *WSHub) close() {
	h.mu.Lock()
	conns := make([]*WSConn, 0, len(h.conns))
	for c := range h.conns {
		conns = append(conns, c)
	}
	h.conns = make(map[*WSConn]struct{})
	h.mu.Unlock()

	for _, c := range conns {
		_ = c.Close()
	}
}

// HandleWS 注册 WebSocket 端点，返回集线器供业务模块广播。
//
// checkOrigin 为跨域校验函数；传 nil 时开发期允许所有来源（生产须收紧）。
//
// 使用示例：
//
//	hub := s.HandleWS("/ws/alerts", nil)
//	hub.SetOnMessage(func(c *transport.WSConn, msg []byte) {
//	    // 处理客户端消息
//	})
//	// 后续某处广播：
//	hub.BroadcastJSON(map[string]any{"level": "L1", "ip": "1.2.3.4"})
func (s *Server) HandleWS(pattern string, checkOrigin func(*http.Request) bool) *WSHub {
	hub := newWSHub()

	var upgrader = websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		CheckOrigin:     checkOrigin,
	}
	if checkOrigin == nil {
		// 开发期默认允许；生产部署应注入严格 checkOrigin
		upgrader.CheckOrigin = func(r *http.Request) bool { return true }
	}

	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			s.logger.Warn("ws upgrade failed", "err", err, "remote", r.RemoteAddr)
			return
		}
		c := &WSConn{conn: conn}
		hub.register(c)

		// 读循环：检测客户端断开，触发注销；收到消息交给 onMessage
		go func() {
			defer func() {
				hub.unregister(c)
				_ = conn.Close()
			}()
			conn.SetReadLimit(1 << 20) // 1MB 消息上限
			_ = conn.SetReadDeadline(time.Now().Add(24 * time.Hour))
			for {
				_, msg, err := conn.ReadMessage()
				if err != nil {
					return
				}
				if hub.onMessage != nil {
					hub.onMessage(c, msg)
				}
			}
		}()
	})

	// 记录 WS 路由，Shutdown 时关闭
	s.mu.Lock()
	s.wsRoutes = append(s.wsRoutes, wsRoute{pattern: pattern, hub: hub})
	s.mu.Unlock()

	return hub
}
