package query

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/storage"
)

// newDetailService 构造一个使用临时 DataDir 的查询服务，并把样本文件复制进去。
//
// 真实样本来自仓库 testdata/attacks；复制到 t.TempDir() 是为了验证
// 「DataDir + CaptureRecord.FilePath」的路径拼装，而不是依赖工作目录。
func newDetailService(t *testing.T, sample, fileName string) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "attacks", sample))
	if err != nil {
		t.Fatalf("读取样本 %s: %v", sample, err)
	}
	if err := os.WriteFile(filepath.Join(dir, fileName), src, 0o644); err != nil {
		t.Fatalf("写入临时样本: %v", err)
	}

	db := newMemStorage()
	db.captures["cap-1"] = &storage.CaptureRecord{
		ID:         "cap-1",
		Name:       sample,
		FilePath:   fileName,
		LinkType:   1,
		ImportedAt: time.Now(),
	}
	return New(db, dir), dir
}

// TestDetail_FirstPacket 取第 1 个包：协议树、十六进制、HTTP 载荷都要有。
func TestDetail_FirstPacket(t *testing.T) {
	s, _ := newDetailService(t, "sqli.pcapng", "sqli.pcapng")

	detail, err := s.PacketDetail(context.Background(), "cap-1", 1)
	if err != nil {
		t.Fatalf("PacketDetail: %v", err)
	}

	if detail.No != 1 {
		t.Errorf("No = %d, want 1", detail.No)
	}
	if detail.LinkType != 1 {
		t.Errorf("LinkType = %d, want 1", detail.LinkType)
	}
	if len(detail.Layers) < 4 {
		t.Fatalf("len(Layers) = %d, want >= 4; layers=%+v", len(detail.Layers), detail.Layers)
	}
	if len(detail.Hex) == 0 {
		t.Fatal("Hex 为空")
	}
	if !strings.Contains(detail.PayloadText, "GET") {
		t.Errorf("PayloadText 未包含请求行: %q", detail.PayloadText)
	}
	if detail.PayloadTruncated {
		t.Error("PayloadTruncated = true, want false（样本载荷远小于 8 KB）")
	}
	if detail.Time == "" {
		t.Error("Time 为空")
	}
	if detail.CapLen <= 0 || detail.OrigLen <= 0 {
		t.Errorf("CapLen/OrigLen = %d/%d, want > 0", detail.CapLen, detail.OrigLen)
	}
}

// TestDetail_LayerNames 协议树至少出现 Ethernet II 与 IPv4，且关键层有 fields。
func TestDetail_LayerNames(t *testing.T) {
	s, _ := newDetailService(t, "sqli.pcapng", "sqli.pcapng")

	detail, err := s.PacketDetail(context.Background(), "cap-1", 1)
	if err != nil {
		t.Fatalf("PacketDetail: %v", err)
	}

	names := make(map[string]bool)
	for _, l := range detail.Layers {
		names[l.Name] = true
	}
	for _, want := range []string{"Frame", "Ethernet II", "Internet Protocol Version 4", "Transmission Control Protocol", "Hypertext Transfer Protocol"} {
		if !names[want] {
			t.Errorf("缺少协议层 %q；实际=%v", want, layerNames(detail.Layers))
		}
	}
	for _, l := range detail.Layers {
		if l.Fields == nil {
			t.Errorf("层 %q 的 fields 为 nil；未知层也必须是空数组", l.Name)
		}
		if l.Name == "Ethernet II" && len(l.Fields) < 3 {
			t.Errorf("Ethernet II fields 太少: %+v", l.Fields)
		}
		if l.Name == "Internet Protocol Version 4" && len(l.Fields) < 4 {
			t.Errorf("IPv4 fields 太少: %+v", l.Fields)
		}
	}

	// HTTP 层必须带请求方法与 URI（不是只填 name）。
	httpFields := map[string]string{}
	for _, l := range detail.Layers {
		if l.Name == "Hypertext Transfer Protocol" {
			for _, f := range l.Fields {
				httpFields[f.K] = f.V
			}
		}
	}
	if httpFields["request.method"] != "GET" {
		t.Errorf("request.method = %q, want GET", httpFields["request.method"])
	}
	if !strings.Contains(httpFields["request.uri"], "/search") {
		t.Errorf("request.uri = %q, want 包含 /search", httpFields["request.uri"])
	}
}

// TestDetail_Errors 校验 400/404 语义（service + handler 两层）。
func TestDetail_Errors(t *testing.T) {
	s, _ := newDetailService(t, "sqli.pcapng", "sqli.pcapng")
	h := s.Handler()

	cases := []struct {
		name string
		url  string
		want int
	}{
		{"no=0", "/api/v1/captures/cap-1/packets/0/detail", http.StatusBadRequest},
		{"no 非整数", "/api/v1/captures/cap-1/packets/abc/detail", http.StatusBadRequest},
		{"no 越界", "/api/v1/captures/cap-1/packets/999/detail", http.StatusNotFound},
		{"未知 capture", "/api/v1/captures/missing/packets/1/detail", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d; body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}

	// service 层也要给出可判定的错误。
	if _, err := s.PacketDetail(context.Background(), "cap-1", 0); err == nil {
		t.Error("no=0 应返回错误")
	}
	if _, err := s.PacketDetail(context.Background(), "cap-1", 999); err == nil {
		t.Error("no=999 应返回错误")
	}
	if _, err := s.PacketDetail(context.Background(), "missing", 1); err == nil {
		t.Error("未知 capture 应返回错误")
	}
}

// TestDetail_HexFormatOnWire 通过 HTTP 校验实际 JSON 输出与十六进制行格式。
func TestDetail_HexFormatOnWire(t *testing.T) {
	s, _ := newDetailService(t, "sqli.pcapng", "sqli.pcapng")
	h := s.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/captures/cap-1/packets/1/detail", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var body struct {
		No      int      `json:"no"`
		Layers  []Layer  `json:"layers"`
		Hex     []string `json:"hex"`
		Payload string   `json:"payload_text"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.No != 1 {
		t.Errorf("no = %d, want 1", body.No)
	}
	if len(body.Layers) == 0 || len(body.Hex) == 0 {
		t.Fatalf("layers/hex 为空: %d/%d", len(body.Layers), len(body.Hex))
	}
	pat := regexp.MustCompile(`^[0-9a-f]{4}  `)
	for i, line := range body.Hex {
		if !pat.MatchString(line) {
			t.Errorf("hex[%d] = %q，不符合 ^[0-9a-f]{4}  ", i, line)
		}
	}
	if !strings.Contains(body.Payload, "HTTP/1.1") {
		t.Errorf("payload_text 未包含 HTTP/1.1: %q", body.Payload)
	}

	// 记录实际 JSON，便于人工核对契约（go test -run Detail -v 可见）。
	t.Logf("完整 JSON 响应:\n%s", rec.Body.String())
	pretty, _ := json.MarshalIndent(body, "", "  ")
	t.Logf("解析后的关键字段:\n%s", pretty)
}

// TestDetail_DNSLayer DNS 样本必须出现 Domain Name System 层且有字段。
func TestDetail_DNSLayer(t *testing.T) {
	s, _ := newDetailService(t, "dnstunnel.pcapng", "dnstunnel.pcapng")

	detail, err := s.PacketDetail(context.Background(), "cap-1", 1)
	if err != nil {
		t.Fatalf("PacketDetail: %v", err)
	}
	var dns *Layer
	for i := range detail.Layers {
		if detail.Layers[i].Name == "Domain Name System" {
			dns = &detail.Layers[i]
			break
		}
	}
	if dns == nil {
		t.Fatalf("缺少 DNS 层；实际=%v", layerNames(detail.Layers))
	}
	fields := map[string]string{}
	for _, f := range dns.Fields {
		fields[f.K] = f.V
	}
	if fields["dns.qry.name"] == "" {
		t.Errorf("DNS 层缺少 dns.qry.name: %+v", dns.Fields)
	}
}

// TestDetail_FileTooLarge 超过 64 MB 直接 413，且不应把文件读进内存。
func TestDetail_FileTooLarge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Truncate(maxDetailFileSize + 1); err != nil {
		_ = f.Close()
		t.Fatalf("truncate: %v", err)
	}
	_ = f.Close()

	db := newMemStorage()
	db.captures["cap-big"] = &storage.CaptureRecord{ID: "cap-big", FilePath: "big.bin"}
	s := New(db, dir)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/captures/cap-big/packets/1/detail", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", rec.Code, rec.Body.String())
	}
}

// TestDetail_SanitizeAndHex 覆盖二进制载荷清洗与十六进制边界。
func TestDetail_SanitizeAndHex(t *testing.T) {
	// 不可打印/非法 UTF-8 用 '.' 替代；\r\n\t 保留。
	input := []byte{'A', 0x00, 0xff, '\r', '\n', '\t', 'Z'}
	got := sanitizeDetailText(input)
	if got != "A..\r\n\tZ" {
		t.Errorf("sanitizeDetailText = %q, want %q", got, "A..\r\n\tZ")
	}

	// 行格式：4 位小写偏移 + 两个空格；不可打印 ASCII 用 '.'。
	lines := formatDetailHex([]byte("Hi\x00"))
	if len(lines) != 1 {
		t.Fatalf("len(lines) = %d, want 1", len(lines))
	}
	if !strings.HasPrefix(lines[0], "0000  ") {
		t.Errorf("line = %q, want 前缀 0000  ", lines[0])
	}
	if !strings.HasSuffix(lines[0], "Hi.") {
		t.Errorf("line = %q, want ASCII 部分 Hi.", lines[0])
	}
}

func layerNames(layers []Layer) []string {
	names := make([]string, 0, len(layers))
	for _, l := range layers {
		names = append(names, l.Name)
	}
	return names
}
