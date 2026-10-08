package l7

import (
	"strings"
	"testing"

	"flow-monitoring/internal/kernel/datamodel"
)

// newL7Packet 构造一个已填 L4 字段的包用于 L7 分发测试。
func newL7Packet(ipProto uint8, srcPort, dstPort uint16, payload []byte) *datamodel.Packet {
	p := datamodel.NewPacket()
	p.IPProto = ipProto
	p.SrcPort = srcPort
	p.DstPort = dstPort
	p.Data = payload
	p.PayloadOff = 0
	p.PayloadLen = len(payload)
	p.CapLen = len(payload)
	p.OrigLen = len(payload)
	return p
}

// dnsQuery 构造 DNS 查询报文。
func dnsQuery(name string, qtype uint16) []byte {
	msg := []byte{0x12, 0x34}           // ID
	msg = append(msg, 0x01, 0x00)       // flags: RD
	msg = append(msg, 0x00, 0x01)       // qdcount = 1
	msg = append(msg, 0, 0, 0, 0, 0, 0) // an/ns/ar = 0
	for _, l := range strings.Split(name, ".") {
		msg = append(msg, byte(len(l)))
		msg = append(msg, l...)
	}
	msg = append(msg, 0x00) // end of name
	msg = append(msg, byte(qtype>>8), byte(qtype))
	msg = append(msg, 0x00, 0x01) // class IN
	return msg
}

// TestDNS_Query 解析 DNS 查询。
func TestDNS_Query(t *testing.T) {
	p := newL7Packet(17, 12345, 53, dnsQuery("example.com", 1))
	Dispatch(p)

	if p.Proto != "DNS" {
		t.Fatalf("Proto = %q, want DNS", p.Proto)
	}
	if p.DNS == nil {
		t.Fatal("DNS should not be nil")
	}
	if p.DNS.QR {
		t.Error("should be query (QR=false)")
	}
	if len(p.DNS.Questions) != 1 {
		t.Fatalf("Questions = %d, want 1", len(p.DNS.Questions))
	}
	q := p.DNS.Questions[0]
	if q.Name != "example.com" {
		t.Errorf("Name = %q, want example.com", q.Name)
	}
	if q.Type != 1 {
		t.Errorf("Type = %d, want 1 (A)", q.Type)
	}
}

// TestDNS_ResponseWithAnswer 解析带 A 记录的响应。
func TestDNS_ResponseWithAnswer(t *testing.T) {
	// 构造响应：ID + flags(QR|RD|RA) + qd=1 + an=1
	msg := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	// question
	msg = append(msg, 0x07)
	msg = append(msg, "example"...)
	msg = append(msg, 0x03)
	msg = append(msg, "com"...)
	msg = append(msg, 0x00)
	msg = append(msg, 0x00, 0x01, 0x00, 0x01) // A IN
	// answer: name 指针(0xc00c) + A + IN + ttl + rdlen=4 + 93.184.216.34
	msg = append(msg, 0xc0, 0x0c)
	msg = append(msg, 0x00, 0x01, 0x00, 0x01) // A IN
	msg = append(msg, 0x00, 0x00, 0x0e, 0x10) // ttl 3600
	msg = append(msg, 0x00, 0x04)             // rdlength 4
	msg = append(msg, 93, 184, 216, 34)       // 93.184.216.34

	p := newL7Packet(17, 53, 12345, msg)
	Dispatch(p)

	if p.DNS == nil || !p.DNS.QR {
		t.Fatal("should be DNS response")
	}
	if len(p.DNS.Answers) != 1 {
		t.Fatalf("Answers = %d, want 1", len(p.DNS.Answers))
	}
	a := p.DNS.Answers[0]
	if a.Data != "93.184.216.34" {
		t.Errorf("Answer Data = %q, want 93.184.216.34", a.Data)
	}
}

// TestDNSName_PointerCompression 域名指针压缩。
func TestDNSName_PointerCompression(t *testing.T) {
	// name 在 offset 12: "example.com"（\x07example\x03com\x00 共 13 字节）
	msg := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	msg = append(msg, 0x07)
	msg = append(msg, "example"...)
	msg = append(msg, 0x03)
	msg = append(msg, "com"...)
	msg = append(msg, 0x00)

	name, next, ok := dnsName(msg, 12)
	if !ok || name != "example.com" {
		t.Errorf("name = %q, ok=%v, want example.com", name, ok)
	}
	if next != 12+13 {
		t.Errorf("next = %d, want %d", next, 12+13)
	}
}

// TestHTTP_Request 解析 HTTP 请求。
func TestHTTP_Request(t *testing.T) {
	req := "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
	p := newL7Packet(6, 12345, 80, []byte(req))
	Dispatch(p)

	if p.Proto != "HTTP" {
		t.Fatalf("Proto = %q, want HTTP", p.Proto)
	}
	if p.HTTP == nil {
		t.Fatal("HTTP should not be nil")
	}
	if !p.HTTP.IsRequest || p.HTTP.Method != "GET" || p.HTTP.URI != "/index.html" {
		t.Errorf("HTTP = %+v, want GET /index.html", p.HTTP)
	}
	if p.HTTP.Host != "example.com" {
		t.Errorf("Host = %q, want example.com", p.HTTP.Host)
	}
	if p.HTTP.UserAgent != "test" {
		t.Errorf("UserAgent = %q, want test", p.HTTP.UserAgent)
	}
}

// TestHTTP_Response 解析 HTTP 响应。
func TestHTTP_Response(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello"
	p := newL7Packet(6, 80, 12345, []byte(resp))
	Dispatch(p)

	if p.Proto != "HTTP" {
		t.Fatalf("Proto = %q, want HTTP", p.Proto)
	}
	if p.HTTP == nil {
		t.Fatal("HTTP should not be nil")
	}
	if p.HTTP.IsRequest {
		t.Error("should be response")
	}
	if p.HTTP.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", p.HTTP.StatusCode)
	}
	if p.HTTP.ContentType != "text/html" {
		t.Errorf("ContentType = %q, want text/html", p.HTTP.ContentType)
	}
	if p.HTTP.ContentLength != 5 {
		t.Errorf("ContentLength = %d, want 5", p.HTTP.ContentLength)
	}
}

// TestHTTP_ByteBounds 验证 HTTP 解析器新增的字节边界数字：
// 按 HeaderLen/BodyOff/URIOff/URILen/MethodOff/MethodLen 从载荷切出的字节，
// 必须与原始报文的头段、正文、URI、Method 逐字节一致；并覆盖无 \r\n\r\n 的
// 截断头（HeaderLen=载荷长度且 <=4096、BodyOff=0）与响应分支（URI/Method 字段为 0）。
func TestHTTP_ByteBounds(t *testing.T) {
	// (a) 带若干头 + 正文的 POST 请求。
	head := "POST /submit?q=1 HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: 14\r\n" +
		"\r\n"
	body := "hello-body-123" // 14 字节，与 Content-Length 一致
	p := newL7Packet(6, 12345, 80, []byte(head+body))
	Dispatch(p)
	if p.HTTP == nil {
		t.Fatal("HTTP should not be nil")
	}
	h := p.HTTP

	if h.HeaderLen != len(head) {
		t.Errorf("HeaderLen = %d, want %d", h.HeaderLen, len(head))
	}
	if got := string(p.Data[:h.HeaderLen]); got != head {
		t.Errorf("按 HeaderLen 切出的头段 = %q, want %q", got, head)
	}
	if h.BodyOff != len(head) {
		t.Errorf("BodyOff = %d, want %d", h.BodyOff, len(head))
	}
	if got := string(p.Data[h.BodyOff:]); got != body {
		t.Errorf("从 BodyOff 起的正文 = %q, want %q", got, body)
	}
	if h.MethodOff != 0 {
		t.Errorf("MethodOff = %d, want 0", h.MethodOff)
	}
	if h.MethodLen != len("POST") {
		t.Errorf("MethodLen = %d, want %d", h.MethodLen, len("POST"))
	}
	if got := string(p.Data[h.MethodOff : h.MethodOff+h.MethodLen]); got != "POST" {
		t.Errorf("按 MethodOff/MethodLen 切出的 Method = %q, want POST", got)
	}
	uri := "/submit?q=1"
	if h.URILen != len(uri) {
		t.Errorf("URILen = %d, want %d", h.URILen, len(uri))
	}
	if h.URIOff != len("POST")+1 {
		t.Errorf("URIOff = %d, want %d", h.URIOff, len("POST")+1)
	}
	if got := string(p.Data[h.URIOff : h.URIOff+h.URILen]); got != uri {
		t.Errorf("按 URIOff/URILen 切出的 URI = %q, want %q", got, uri)
	}

	// (b) 找不到 \r\n\r\n 的截断头（只有请求行 + 一个头，无空行）。
	trunc := "GET /truncated HTTP/1.1\r\nHost: example.com"
	p2 := newL7Packet(6, 12345, 80, []byte(trunc))
	Dispatch(p2)
	if p2.HTTP == nil {
		t.Fatal("HTTP should not be nil")
	}
	h2 := p2.HTTP
	if h2.HeaderLen != len(trunc) {
		t.Errorf("截断头 HeaderLen = %d, want %d", h2.HeaderLen, len(trunc))
	}
	if h2.HeaderLen > 4096 {
		t.Errorf("截断头 HeaderLen = %d, want <= 4096", h2.HeaderLen)
	}
	if h2.BodyOff != 0 {
		t.Errorf("截断头 BodyOff = %d, want 0", h2.BodyOff)
	}

	// (c) 响应报文：HeaderLen 正常（含到 \r\n\r\n 为止），
	// URI/Method 相关字段全为 0（走响应分支）。
	respHead := "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
	p3 := newL7Packet(6, 80, 12345, []byte(respHead))
	Dispatch(p3)
	if p3.HTTP == nil {
		t.Fatal("HTTP should not be nil")
	}
	h3 := p3.HTTP
	if h3.HeaderLen != len(respHead) {
		t.Errorf("响应 HeaderLen = %d, want %d", h3.HeaderLen, len(respHead))
	}
	if got := string(p3.Data[:h3.HeaderLen]); got != respHead {
		t.Errorf("响应按 HeaderLen 切出的头段 = %q, want %q", got, respHead)
	}
	if h3.BodyOff != len(respHead) {
		t.Errorf("响应 BodyOff = %d, want %d", h3.BodyOff, len(respHead))
	}
	if h3.URIOff != 0 || h3.URILen != 0 || h3.MethodOff != 0 || h3.MethodLen != 0 {
		t.Errorf("响应 URI/Method 边界应全为 0, got URIOff=%d URILen=%d MethodOff=%d MethodLen=%d",
			h3.URIOff, h3.URILen, h3.MethodOff, h3.MethodLen)
	}
}

// TestTLS_ClientHelloSNI 提取 ClientHello SNI。
func TestTLS_ClientHelloSNI(t *testing.T) {
	// 构造 ClientHello body
	body := make([]byte, 0, 128)
	body = append(body, 0x03, 0x03)             // version TLS1.2
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session_id_len = 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites_len=2, TLS_AES_128_GCM
	body = append(body, 0x01, 0x00)             // compression_len=1, null
	// SNI extension
	sniName := []byte("example.com")
	extData := make([]byte, 0)
	extData = append(extData, 0x00, byte(len(sniName)+3)) // server_name_list_len (name_type+len+name)
	extData = append(extData, 0x00)                       // name_type host_name
	extData = append(extData, byte(len(sniName)>>8), byte(len(sniName)))
	extData = append(extData, sniName...)
	// extension: type=0(SNI), len
	ext := make([]byte, 0)
	ext = append(ext, 0x00, 0x00)
	ext = append(ext, byte(len(extData)>>8), byte(len(extData)))
	ext = append(ext, extData...)
	body = append(body, byte(len(ext)>>8), byte(len(ext))) // extensions_len
	body = append(body, ext...)

	// handshake: type=1 + length(3) + body
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	// TLS record: 0x16 0x03 0x01 + length + handshake
	record := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	record = append(record, hs...)

	p := newL7Packet(6, 12345, 443, record)
	Dispatch(p)

	if p.TLS == nil {
		t.Fatal("TLS should not be nil")
	}
	if p.TLS.SNI != "example.com" {
		t.Errorf("SNI = %q, want example.com", p.TLS.SNI)
	}
	if p.TLS.HandshakeType != 1 {
		t.Errorf("HandshakeType = %d, want 1 (ClientHello)", p.TLS.HandshakeType)
	}
	// Proto 应为 TLS 版本名
	if !strings.HasPrefix(p.Proto, "TLS") {
		t.Errorf("Proto = %q, want TLS*", p.Proto)
	}
}

// TestDispatch_UDPPortDNS 端口 53 走 DNS。
func TestDispatch_UDPPortDNS(t *testing.T) {
	// 端口 5353 (mDNS) 也走 DNS
	p := newL7Packet(17, 5353, 5353, dnsQuery("local", 1))
	Dispatch(p)
	if p.Proto != "DNS" {
		t.Errorf("Proto = %q, want DNS (mDNS)", p.Proto)
	}
}

// TestDispatch_UnknownPayload 未知载荷保留 L4 判定（不 panic）。
func TestDispatch_UnknownPayload(t *testing.T) {
	p := newL7Packet(6, 12345, 9999, []byte{0x01, 0x02, 0x03, 0x04})
	Dispatch(p) // 不应 panic
	// 未识别时 Proto 保持原值（这里构造时未填，所以为空是预期）
	_ = p.Proto
}
