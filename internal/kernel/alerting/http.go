package alerting

// 两条查询路由：
//
//	GET /api/alerts?page=1&page_size=50&since_id=0
//	GET /api/alerts/stats
//
// 与 /api/modules 风格一致：内核直接挂在宿主 mux 上，不经过模块进程网关。

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// Registrar 是路由注册所需的最小接口（*transport.Server 天然满足）。
type Registrar interface {
	HandleFunc(methodPattern string, fn http.HandlerFunc)
}

// Register 把告警查询路由注册到宿主的 HTTP mux。
func (s *Service) Register(m Registrar) {
	if s == nil || m == nil {
		return
	}
	m.HandleFunc("GET /api/alerts", s.handleAlerts)
	m.HandleFunc("GET /api/alerts/stats", s.handleStats)
}

// handleAlerts GET /api/alerts
func (s *Service) handleAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := intQuery(q.Get("page"), 1)
	pageSize := intQuery(q.Get("page_size"), DefaultPageSize)
	sinceID := uintQuery(q.Get("since_id"), 0)
	writeJSON(w, http.StatusOK, s.Query(page, pageSize, sinceID))
}

// handleStats GET /api/alerts/stats
func (s *Service) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Stats())
}

// intQuery 解析 int 查询参数；缺省或非法一律回退默认值（不报 400）。
func intQuery(v string, def int) int {
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// uintQuery 解析 uint64 查询参数；缺省或非法一律回退默认值。
func uintQuery(v string, def uint64) uint64 {
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

// writeJSON 统一 JSON 响应（与 transport.WriteJSON 行为一致，避免包间耦合）。
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
