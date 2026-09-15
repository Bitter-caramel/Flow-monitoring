package transport

import (
	"context"
	"encoding/json"
	"net/http"
)

// contextKey 请求上下文键类型（避免字符串键冲突）。
type contextKey string

const ctxRequestID contextKey = "request_id"

// withRequestID 把 request_id 写入 context。
func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxRequestID, id)
}

// RequestIDFrom 从 context 读取 request_id（无则返回空字符串）。
func RequestIDFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(ctxRequestID).(string); ok {
		return v
	}
	return ""
}

// encodeJSON 编码 JSON 到 w。
func encodeJSON(w http.ResponseWriter, v any) error {
	return json.NewEncoder(w).Encode(v)
}
