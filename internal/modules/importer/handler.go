package importer

import (
	"encoding/json"
	"io"
	"net/http"
)

// ImportHandler 返回 HTTP 上传接口（multipart form）。
//
// 用法：POST /api/v1/captures/import
//
//	Content-Type: multipart/form-data
//	字段：file（pcap/pcapng 文件，必填）、name（可选名称）
//
// 成功返回 storage.CaptureRecord JSON。
func (i *Importer) ImportHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 限制 256MB 上传
		if err := r.ParseMultipartForm(256 << 20); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parse multipart: " + err.Error()})
			return
		}

		file, header, err := r.FormFile("file")
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing file field: " + err.Error()})
			return
		}
		defer file.Close()

		data, err := io.ReadAll(file)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read file: " + err.Error()})
			return
		}

		name := r.FormValue("name")
		if name == "" {
			name = header.Filename
		}

		rec, err := i.Import(r.Context(), "", name, data)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, rec)
	}
}

// writeJSON 输出 JSON。
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
