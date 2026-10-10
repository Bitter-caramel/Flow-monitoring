package detect

import (
	"bytes"
	"errors"
	"testing"

	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/modules/rule"
)

// mustExtract 通过缓冲区名查表并执行提取器，顺带验证注册表本身。
func mustExtract(t *testing.T, buf rule.Buffer, c *Ctx) []byte {
	t.Helper()
	fn, ok := LookupBuffer(buf)
	if !ok {
		t.Fatalf("缓冲区未注册: %s", buf)
	}
	return fn(c)
}

// 验证 a)：真实 HTTP 请求载荷下，五个提取器取出的字节与原文一致（含前缀字节的偏移）。
func TestExtractorsHTTPRequest(t *testing.T) {
	const (
		method = "GET"
		uri    = "/index.html?q=1"
		body   = "hello"
	)
	reqLine := method + " " + uri + " HTTP/1.1\r\n"
	headerTail := "Host: example.com\r\nUser-Agent: test\r\nContent-Length: 5\r\n\r\n"
	header := reqLine + headerTail
	payload := header + body

	prefix := []byte{0xde, 0xad, 0xbe, 0xef} // 载荷前夹杂的其它字节（如 TCP/IP 头）
	data := append(append([]byte{}, prefix...), payload...)

	p := &datamodel.Packet{
		Data:       data,
		PayloadOff: len(prefix),
		PayloadLen: len(payload),
		HTTP: &datamodel.HTTP{
			IsRequest: true,
			Method:    method,
			URI:       uri,
			HeaderLen: len(header),
			BodyOff:   len(header),
			URIOff:    len(method) + 1, // 跳过 "GET "
			URILen:    len(uri),
			MethodOff: 0,
			MethodLen: len(method),
		},
	}
	c := &Ctx{Pkt: p, Flow: &datamodel.Flow{}}

	// payload：整个应用层载荷应等于原文
	if got := mustExtract(t, rule.BufPayload, c); !bytes.Equal(got, []byte(payload)) {
		t.Fatalf("payload 不匹配: got=%q want=%q", got, payload)
	}
	// http_header：头段应等于请求行 + 头（含结尾空行）
	if got := mustExtract(t, rule.BufHTTPHeader, c); !bytes.Equal(got, []byte(header)) {
		t.Fatalf("http_header 不匹配: got=%q want=%q", got, header)
	}
	// http_client_body：正文应等于 body
	if got := mustExtract(t, rule.BufHTTPClientBody, c); !bytes.Equal(got, []byte(body)) {
		t.Fatalf("http_client_body 不匹配: got=%q want=%q", got, body)
	}
	// http_uri：URI 应等于 /index.html?q=1
	if got := mustExtract(t, rule.BufHTTPURI, c); !bytes.Equal(got, []byte(uri)) {
		t.Fatalf("http_uri 不匹配: got=%q want=%q", got, uri)
	}
	// http_method：方法应等于 GET
	if got := mustExtract(t, rule.BufHTTPMethod, c); !bytes.Equal(got, []byte(method)) {
		t.Fatalf("http_method 不匹配: got=%q want=%q", got, method)
	}
}

// 验证 b)：非 HTTP 包（HTTP == nil）时，四个 HTTP 缓冲提取器全部返回 nil。
func TestHTTPExtractorsNonHTTP(t *testing.T) {
	p := &datamodel.Packet{
		Data:       []byte("abcdefghij"),
		PayloadOff: 2,
		PayloadLen: 6,
		// HTTP == nil
	}
	c := &Ctx{Pkt: p}
	for _, buf := range []rule.Buffer{
		rule.BufHTTPHeader,
		rule.BufHTTPClientBody,
		rule.BufHTTPURI,
		rule.BufHTTPMethod,
	} {
		if got := mustExtract(t, buf, c); got != nil {
			t.Fatalf("非 HTTP 包 %s 应为 nil, got=%q", buf, got)
		}
	}
}

// 验证 c)：空正文（HeaderLen == PayloadLen）时 http_client_body 返回 nil 而非空切片。
func TestHTTPClientBodyEmpty(t *testing.T) {
	header := "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
	p := &datamodel.Packet{
		Data:       []byte(header),
		PayloadOff: 0,
		PayloadLen: len(header),
		HTTP: &datamodel.HTTP{
			HeaderLen: len(header),
			BodyOff:   len(header), // 正文起点等于载荷末尾 => 空正文
			URIOff:    len("GET "),
			URILen:    1,
			MethodOff: 0,
			MethodLen: len("GET"),
		},
	}
	if got := mustExtract(t, rule.BufHTTPClientBody, &Ctx{Pkt: p}); got != nil {
		t.Fatalf("空正文应为 nil, got=%q", got)
	}
}

// 验证 d)：dns_query 在 Questions 有 1 项时返回该 Name，为空或非 DNS 包时返回 nil。
func TestDNSQuery(t *testing.T) {
	c := &Ctx{Pkt: &datamodel.Packet{
		DNS: &datamodel.DNS{Questions: []datamodel.DNSQuestion{{Name: "example.com", Type: 1, Class: 1}}},
	}}
	if got := mustExtract(t, rule.BufDNSQuery, c); !bytes.Equal(got, []byte("example.com")) {
		t.Fatalf("dns_query 不匹配: got=%q", got)
	}
	empty := &Ctx{Pkt: &datamodel.Packet{DNS: &datamodel.DNS{}}}
	if got := mustExtract(t, rule.BufDNSQuery, empty); got != nil {
		t.Fatalf("空 Questions 应为 nil, got=%q", got)
	}
	if got := mustExtract(t, rule.BufDNSQuery, &Ctx{Pkt: &datamodel.Packet{}}); got != nil {
		t.Fatalf("非 DNS 包应为 nil, got=%q", got)
	}
}

// 验证 e)：tls_sni 在 SNI 非空时返回它，SNI == "" 或非 TLS 包时返回 nil。
func TestTLSSNI(t *testing.T) {
	c := &Ctx{Pkt: &datamodel.Packet{TLS: &datamodel.TLS{SNI: "example.com"}}}
	if got := mustExtract(t, rule.BufTLSSNI, c); !bytes.Equal(got, []byte("example.com")) {
		t.Fatalf("tls_sni 不匹配: got=%q", got)
	}
	if got := mustExtract(t, rule.BufTLSSNI, &Ctx{Pkt: &datamodel.Packet{TLS: &datamodel.TLS{}}}); got != nil {
		t.Fatalf("空 SNI 应为 nil, got=%q", got)
	}
	if got := mustExtract(t, rule.BufTLSSNI, &Ctx{Pkt: &datamodel.Packet{}}); got != nil {
		t.Fatalf("非 TLS 包应为 nil, got=%q", got)
	}
}

// 验证 f)：越界/负偏移/nil 包时 payload 提取器返回 nil，绝不 panic。
func TestExtractPayloadOutOfBounds(t *testing.T) {
	over := &datamodel.Packet{Data: []byte("short"), PayloadOff: 2, PayloadLen: 100}
	if got := mustExtract(t, rule.BufPayload, &Ctx{Pkt: over}); got != nil {
		t.Fatalf("越界载荷应为 nil, got=%q", got)
	}
	neg := &datamodel.Packet{Data: []byte("short"), PayloadOff: -3, PayloadLen: 4}
	if got := mustExtract(t, rule.BufPayload, &Ctx{Pkt: neg}); got != nil {
		t.Fatalf("负偏移应为 nil, got=%q", got)
	}
	if got := mustExtract(t, rule.BufPayload, &Ctx{}); got != nil {
		t.Fatalf("nil Pkt 应为 nil, got=%q", got)
	}
}

// 验证 g)：Compile 把缓冲名真正换成函数指针（Cond.Extract 非 nil），并能取出字节。
func TestCompileBindsExtractor(t *testing.T) {
	cr := &rule.CompiledRule{
		Rule: rule.Rule{ID: "r1", Name: "demo", Severity: "high"},
		Matchers: []rule.Matcher{
			{Kind: rule.CondContent, Buffer: rule.BufPayload, Content: "GET"},
		},
	}
	prog, err := Compile(cr)
	if err != nil {
		t.Fatalf("Compile 失败: %v", err)
	}
	if len(prog.Conds) != 1 {
		t.Fatalf("Conds 数量 = %d, want 1", len(prog.Conds))
	}
	if prog.Conds[0].Extract == nil {
		t.Fatal("Cond.Extract 为 nil：缓冲名没有换成函数指针")
	}
	pkt := &datamodel.Packet{Data: []byte("GET /"), PayloadOff: 0, PayloadLen: 5}
	if got := prog.Conds[0].Extract(&Ctx{Pkt: pkt}); !bytes.Equal(got, []byte("GET /")) {
		t.Fatalf("绑定后的提取器结果不对: got=%q", got)
	}
}

// 验证 g)：未知缓冲名时 Compile 返回被 %w 包住的 ErrUnsupportedBuffer。
func TestCompileUnsupportedBuffer(t *testing.T) {
	cr := &rule.CompiledRule{
		Matchers: []rule.Matcher{
			{Kind: rule.CondContent, Buffer: rule.Buffer("no_such_buffer"), Content: "x"},
		},
	}
	if _, err := Compile(cr); !errors.Is(err, ErrUnsupportedBuffer) {
		t.Fatalf("err = %v, want errors.Is(err, ErrUnsupportedBuffer)", err)
	}
}

// 验证：Compile(nil) 与空 matchers 都返回 error（防御性）。
func TestCompileNilAndEmpty(t *testing.T) {
	if _, err := Compile(nil); err == nil {
		t.Fatal("Compile(nil) 应返回 error")
	}
	if _, err := Compile(&rule.CompiledRule{}); err == nil {
		t.Fatal("空 matchers 应返回 error")
	}
}
