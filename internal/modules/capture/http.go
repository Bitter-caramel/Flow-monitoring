package capture

import (
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
)

// httpBase 是本模块对外的 HTTP 路由前缀，须与 registry/backend-modules/capture.json
// 的 http_base 保持一致（宿主网关按该前缀反代到本模块进程）。
const httpBase = "/api/capture"

// handler 返回 capture 的 Run 管理路由。
//
// 路由由本模块进程自己监听，宿主网关反代 /api/capture/*，模块无需自己监听端口。
func (m *captureModule) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+httpBase+"/runs", m.handleListRuns)
	mux.HandleFunc("POST "+httpBase+"/runs", m.handleCreateRun)
	mux.HandleFunc("GET "+httpBase+"/runs/{id}", m.handleGetRun)
	mux.HandleFunc("DELETE "+httpBase+"/runs/{id}", m.handleDeleteRun)
	return mux
}

// runsResponse 是 GET /runs 的响应体。
type runsResponse struct {
	Items []runView `json:"items"`
	Total int       `json:"total"`
}

// createRunRequest 是 POST /runs 的请求体。
//
// ★ 只接受 capture_id（已导入抓包的 ID），绝不接受客户端直接传文件路径。
type createRunRequest struct {
	Mode      string `json:"mode"`
	CaptureID string `json:"capture_id"`
}

// handleListRuns GET /api/capture/runs
func (m *captureModule) handleListRuns(w http.ResponseWriter, _ *http.Request) {
	items := m.listRuns()
	writeJSON(w, http.StatusOK, runsResponse{Items: items, Total: len(items)})
}

// handleCreateRun POST /api/capture/runs
//
// 解析 capture_id → 查宿主存储拿 FilePath → 拼绝对路径 → 建 static Run。
func (m *captureModule) handleCreateRun(w http.ResponseWriter, r *http.Request) {
	var req createRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "请求体不是合法 JSON: " + err.Error(),
		})
		return
	}

	mode := req.Mode
	if mode == "" {
		mode = modeStatic
	}
	if mode != modeStatic {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "不支持的 mode: " + mode + "（当前仅支持 static）",
		})
		return
	}
	if req.CaptureID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "capture_id 不能为空"})
		return
	}

	host := m.host
	if host == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "宿主桥未就绪"})
		return
	}
	rec, ok := host.CaptureGet(req.CaptureID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "capture_id 不存在"})
		return
	}

	// ★ 路径由「宿主下发的 DataDir + 可信存储里的 FilePath」拼出，不接受客户端路径。
	absPath := filepath.Join(m.getDataDir(), rec.FilePath)
	src, err := m.openSource(absPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "打开抓包文件失败: " + err.Error(),
		})
		return
	}

	run, err := m.addRun(modeStatic, rec.Name, rec.ID, src)
	if err != nil {
		_ = src.Close()
		if errors.Is(err, errTooManyRuns) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	view, _ := m.getRun(run.ID)
	writeJSON(w, http.StatusCreated, view)
}

// handleGetRun GET /api/capture/runs/{id}
func (m *captureModule) handleGetRun(w http.ResponseWriter, r *http.Request) {
	view, ok := m.getRun(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "run 不存在"})
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// handleDeleteRun DELETE /api/capture/runs/{id}
//
// 停止 Run（state 变 done），幂等：重复删除同一个 Run 仍返回 200。
func (m *captureModule) handleDeleteRun(w http.ResponseWriter, r *http.Request) {
	view, ok := m.stopRun(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "run 不存在"})
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// writeJSON 输出 JSON。
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
