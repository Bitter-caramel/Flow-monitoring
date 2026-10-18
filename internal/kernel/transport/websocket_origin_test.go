package transport

import (
	"net/http/httptest"
	"testing"
)

// TestSameOriginCheck 覆盖任务的三种情形：同源 ⇒ true；不同源 ⇒ false；空 Origin ⇒ true。
func TestSameOriginCheck(t *testing.T) {
	cases := []struct {
		name   string
		origin string // 空字符串 = 不带 Origin 头（非浏览器客户端）
		host   string
		want   bool
	}{
		{name: "同源", origin: "http://example.com", host: "example.com", want: true},
		{name: "同源含端口", origin: "http://127.0.0.1:18082", host: "127.0.0.1:18082", want: true},
		{name: "不同源", origin: "http://evil.example", host: "example.com", want: false},
		{name: "空 Origin 视为同源", origin: "", host: "example.com", want: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://"+c.host+"/api/ws/alerts", nil)
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if got := SameOriginCheck(r); got != c.want {
				t.Fatalf("SameOriginCheck(origin=%q, host=%q) = %v, want %v",
					c.origin, c.host, got, c.want)
			}
		})
	}
}
