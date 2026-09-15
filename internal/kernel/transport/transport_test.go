package transport

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"flow-monitoring/internal/kernel/logging"
)

// newTestServer 创建测试用 Server（logger 输出到 buffer）。
func newTestServer(t *testing.T) (*Server, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	logger := logging.New(logging.LevelInfo, "json", &buf)
	s := New(":0", logger)
	if s == nil {
		t.Fatal("New returned nil")
	}
	return s, &buf
}

// TestHTTPRoute 注册路由 → 请求 → 响应 + request_id 头。
func TestHTTPRoute(t *testing.T) {
	s, _ := newTestServer(t)
	s.HandleFunc("GET /api/test", func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, map[string]string{"hello": "world"})
	})

	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/test")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if id := resp.Header.Get("X-Request-ID"); id == "" {
		t.Error("X-Request-ID should not be empty")
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["hello"] != "world" {
		t.Errorf("body = %v, want hello=world", body)
	}
}

// TestHTTPRoute_MethodMismatch 方法不匹配返回 405。
func TestHTTPRoute_MethodMismatch(t *testing.T) {
	s, _ := newTestServer(t)
	s.HandleFunc("GET /api/only-get", func(w http.ResponseWriter, r *http.Request) {})

	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/only-get", "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

// TestHTTPRoute_PathParam 路径参数提取（Go 1.22 ServeMux）。
func TestHTTPRoute_PathParam(t *testing.T) {
	s, _ := newTestServer(t)
	s.HandleFunc("GET /api/items/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		WriteJSON(w, http.StatusOK, map[string]string{"id": id})
	})

	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/items/42")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["id"] != "42" {
		t.Errorf("id = %q, want 42", body["id"])
	}
}

// TestHTTPRoute_PanicRecover panic 被 recover，返回 500 而非崩溃。
func TestHTTPRoute_PanicRecover(t *testing.T) {
	s, _ := newTestServer(t)
	s.HandleFunc("GET /api/panic", func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})

	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/panic")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

// TestWebSocket_Broadcast WS 连接 + 广播。
func TestWebSocket_Broadcast(t *testing.T) {
	s, _ := newTestServer(t)
	hub := s.HandleWS("/ws/test", nil)

	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	wsURL := "ws" + ts.URL[len("http"):] + "/ws/test"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	defer conn.Close()

	// 等待连接注册
	deadline := time.Now().Add(time.Second)
	for hub.Count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hub.Count() != 1 {
		t.Fatalf("hub.Count = %d, want 1", hub.Count())
	}

	// 广播 JSON
	hub.BroadcastJSON(map[string]any{"level": "L1"})

	// 客户端读取
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read ws: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(msg, &got); err != nil {
		t.Fatalf("unmarshal ws msg: %v", err)
	}
	if got["level"] != "L1" {
		t.Errorf("level = %v, want L1", got["level"])
	}
}

// TestWebSocket_ShutdownCloses WS 连接在 Shutdown 时关闭。
func TestWebSocket_ShutdownCloses(t *testing.T) {
	s, _ := newTestServer(t)
	hub := s.HandleWS("/ws/test", nil)

	ts := httptest.NewServer(s.Handler())

	wsURL := "ws" + ts.URL[len("http"):] + "/ws/test"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(time.Second)
	for hub.Count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hub.Count() != 1 {
		t.Fatalf("hub.Count = %d, want 1", hub.Count())
	}

	// 关闭 httptest server（触发 handler 被卸载，但 hub 需显式 close）
	// 注意：这里直接测 hub.close 的效果
	ts.Close()

	// hub 仍持连接，直到 close 调用
	hubCountAfterTSClose := hub.Count()
	_ = hubCountAfterTSClose // 读循环会因 ts 关闭而触发 unregister，但时序不定

	// 显式关闭 hub，确保连接关闭
	s.mu.Lock()
	hub.close()
	s.mu.Unlock()

	// 关闭后 Count 应为 0
	if hub.Count() != 0 {
		t.Errorf("hub.Count after close = %d, want 0", hub.Count())
	}
}

// TestRequestIDFrom 未注入时返回空。
func TestRequestIDFrom(t *testing.T) {
	if got := RequestIDFrom(nil); got != "" {
		t.Errorf("RequestIDFrom(nil) = %q, want empty", got)
	}
}
