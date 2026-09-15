package l7

import (
	"fmt"
	"strconv"
	"strings"

	"flow-monitoring/internal/kernel/datamodel"
)

// httpMethods 常见 HTTP 方法（对应 PacketLens METH 表）。
var httpMethods = []string{
	"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE",
	"PATCH", "CONNECT", "PROPFIND", "REPORT", "SUBSCRIBE", "NOTIFY",
	"M-SEARCH", "DESCRIBE", "ANNOUNCE", "SETUP", "PLAY", "PAUSE",
	"RECORD", "TEARDOWN",
}

// httpLike 检测 HTTP 报文（对应 PacketLens httpLike() index.html:3354）。
// 返回 1=请求, 2=响应, 0=非 HTTP。
func httpLike(b []byte) int {
	if len(b) < 5 {
		return 0
	}
	if hasPrefix(b, "HTTP/") {
		return 2
	}
	for _, m := range httpMethods {
		if hasPrefix(b, m+" ") {
			return 1
		}
	}
	return 0
}

// http 解析 HTTP 报文（对应 PacketLens http() index.html:3366）。
func http(p *datamodel.Packet, b []byte, dir int) {
	h := &datamodel.HTTP{}

	// 找 header 结束位置 \r\n\r\n
	headerEnd := findHeaderEnd(b)
	headerLen := headerEnd
	if headerEnd < 0 {
		headerLen = len(b)
		if headerLen > 4096 {
			headerLen = 4096
		}
	}

	headerText := string(b[:headerLen])
	lines := strings.Split(headerText, "\r\n")
	if len(lines) == 0 {
		p.Proto = "HTTP"
		return
	}

	first := lines[0]

	// 解析头部字段
	headers := map[string]string{}
	for i := 1; i < len(lines); i++ {
		ln := lines[i]
		ci := strings.Index(ln, ":")
		if ci > 0 {
			key := strings.ToLower(strings.TrimSpace(ln[:ci]))
			val := strings.TrimSpace(ln[ci+1:])
			headers[key] = val
		}
	}

	if dir == 1 { // 请求
		parts := strings.SplitN(first, " ", 3)
		if len(parts) >= 2 {
			h.IsRequest = true
			h.Method = parts[0]
			h.URI = parts[1]
		}
	} else if dir == 2 { // 响应
		parts := strings.SplitN(first, " ", 3)
		if len(parts) >= 2 {
			code, err := strconv.Atoi(parts[1])
			if err == nil {
				h.StatusCode = code
			}
			if len(parts) >= 3 {
				h.StatusText = parts[2]
			}
		}
	}

	h.Host = headers["host"]
	h.UserAgent = headers["user-agent"]
	h.ContentType = headers["content-type"]
	if cl, err := strconv.ParseInt(headers["content-length"], 10, 64); err == nil {
		h.ContentLength = cl
	}

	p.HTTP = h
	p.Proto = "HTTP"

	// Info 摘要
	if dir == 1 {
		p.Info = fmt.Sprintf("%s %s HTTP/1.x", h.Method, h.URI)
	} else {
		p.Info = fmt.Sprintf("HTTP/1.x %d %s", h.StatusCode, h.StatusText)
	}
	if h.Host != "" {
		p.Info += " Host: " + h.Host
	}
}

// findHeaderEnd 返回 \r\n\r\n 的位置（header 结束），未找到返回 -1。
func findHeaderEnd(b []byte) int {
	for i := 0; i+3 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' && b[i+2] == '\r' && b[i+3] == '\n' {
			return i
		}
	}
	return -1
}
