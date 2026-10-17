package query

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"flow-monitoring/internal/kernel/storage"
	"flow-monitoring/pkg/plugin"
)

// pageResponse 分页响应体。
type pageResponse[T any] struct {
	Items  []T `json:"items"`
	Total  int `json:"total"`
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
}

// Handler 返回 query 服务的 HTTP 路由。
//
// 注册到 transport.Server 使用：
//
//	transportServer.HandleFunc("/api/v1/", query.Handler().ServeHTTP)
//
// 或直接 mux := query.Handler()。
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/captures", s.handleListCaptures)
	mux.HandleFunc("GET /api/v1/captures/{id}", s.handleGetCapture)
	mux.HandleFunc("GET /api/v1/captures/{id}/packets", s.handleListPackets)

	return mux
}

// handleListCaptures GET /api/v1/captures
func (s *Service) handleListCaptures(w http.ResponseWriter, r *http.Request) {
	page := parsePage(r)
	if page.Limit <= 0 {
		page.Limit = 50
	}
	res, err := s.ListCaptures(r.Context(), page)
	if err != nil {
		writeError(w, err)
		return
	}
	// ★ total 必须是真实条数，不再把 -1 哨兵透给前端。
	// 正常实现（PG / hoststore）的 List 已返回真实 Total；这里再做一次
	// 能力探测兜底，兼容仍返回 -1 的旧实现。
	total := res.Total
	if total < 0 {
		if counter, ok := s.db.Captures().(storage.CaptureCounter); ok {
			if n, err := counter.Count(r.Context()); err == nil {
				total = n
			}
		}
	}
	if total < 0 {
		// 最后一层兜底：当前页不满 ⇒ 不可能还有更多记录。
		total = page.Offset + len(res.Items)
	}
	writeJSON(w, http.StatusOK, pageResponse[storage.CaptureRecord]{
		Items:  res.Items,
		Total:  total,
		Offset: page.Offset,
		Limit:  page.Limit,
	})
}

// handleGetCapture GET /api/v1/captures/{id}
func (s *Service) handleGetCapture(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, err := s.GetCapture(r.Context(), id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

// handleListPackets GET /api/v1/captures/{id}/packets
func (s *Service) handleListPackets(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	page := parsePage(r)
	if page.Limit <= 0 {
		page.Limit = 100
	}
	res, err := s.ListPackets(r.Context(), id, page)
	if err != nil {
		writeError(w, err)
		return
	}
	// total 为 -1（未统计）时主动统计；统计失败也不能把 -1 透给前端。
	total := res.Total
	if total < 0 {
		if n, err := s.CountPackets(r.Context(), id); err == nil {
			total = n
		} else {
			total = page.Offset + len(res.Items)
		}
	}
	writeJSON(w, http.StatusOK, pageResponse[storage.PacketRecord]{
		Items:  res.Items,
		Total:  total,
		Offset: page.Offset,
		Limit:  page.Limit,
	})
}

// parsePage 从 query string 解析分页参数。
func parsePage(r *http.Request) storage.Page {
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if offset < 0 {
		offset = 0
	}
	return storage.Page{Offset: offset, Limit: limit}
}

// writeJSON 输出 JSON。
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError 输出错误（RFC 7807 风格简化版）。
func writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, plugin.ErrStorageUnavailable):
		// ★ 存储不可用必须明确告诉调用方（503），绝不能伪装成 200 + 空列表。
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage unavailable"})
	case errors.Is(err, storage.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
}
