package situation

import (
	"encoding/json"
	"net/http"
)

// handler 返回模块对外的 HTTP 路由（宿主网关按 httpBase 反代到这里）。
//
//	GET /api/situation       当前态势列表（按 score 降序）
//	GET /api/situation/stats 引擎统计
//
// ★ 查询路径不发布 situation.level 事件：发布由消费路径负责（避免在 HTTP 请求里
// 因 Publish 阻塞而拖慢响应）。
func (m *situationModule) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/situation", m.handleItems)
	mux.HandleFunc("GET /api/situation/stats", m.handleStats)
	return mux
}

// handleItems GET /api/situation
func (m *situationModule) handleItems(w http.ResponseWriter, _ *http.Request) {
	items, _ := m.eng.snapshot() // 查询顺带做过期剪枝；产生的降级事件丢弃
	if items == nil {
		items = []item{} // ★ 空时必须是 []，不能是 null
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"total": len(items),
	})
}

// handleStats GET /api/situation/stats
func (m *situationModule) handleStats(w http.ResponseWriter, _ *http.Request) {
	st := m.eng.stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":       true,
		"window_sec":    st.WindowSec,
		"tracked_ips":   st.TrackedIPs,
		"level_changes": st.LevelChanges,
		"received":      st.Received,
		"decode_errors": st.DecodeErrors,
		"top_score":     st.TopScore,
	})
}

// writeJSON 输出 JSON（与其它模块保持一致的 Content-Type）。
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
