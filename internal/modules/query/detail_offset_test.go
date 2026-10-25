package query

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/kernel/storage"
	"flow-monitoring/internal/modules/parse/pcapng"
)

// readSqliFirstPacket 读取 sqli.pcapng 并返回原始字节与第 1 包（含 Offset/CapLen）。
func readSqliFirstPacket(t *testing.T) ([]byte, *datamodel.Packet) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "attacks", "sqli.pcapng"))
	if err != nil {
		t.Fatalf("读取 sqli.pcapng: %v", err)
	}
	c, err := pcapng.Parse(data, 0)
	if err != nil {
		t.Fatalf("Parse sqli.pcapng: %v", err)
	}
	if len(c.Packets) == 0 {
		t.Fatal("sqli.pcapng 未解析出包")
	}
	return data, c.Packets[0]
}

// writeSparsePacketFile 造一个 size 字节的稀疏文件，并把 raw 写到 offset 处，
// 用于模拟"大于 64 MB、但只有目标包有真实字节"的大抓包文件。
func writeSparsePacketFile(t *testing.T, path string, size int64, offset int, raw []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create sparse file: %v", err)
	}
	defer f.Close()
	if err := f.Truncate(size); err != nil {
		t.Fatalf("truncate sparse file: %v", err)
	}
	if _, err := f.WriteAt(raw, int64(offset)); err != nil {
		t.Fatalf("write packet at offset %d: %v", offset, err)
	}
}

// TestDetail_OffsetSeek C2：有 offset 时只 Seek 读一个包，70 MB 文件不再 413。
func TestDetail_OffsetSeek(t *testing.T) {
	_, first := readSqliFirstPacket(t)

	dir := t.TempDir()
	const bigSize = int64(70 << 20) // 70 MB > maxDetailFileSize
	writeSparsePacketFile(t, filepath.Join(dir, "big.pcapng"), bigSize, first.Offset, first.Data)

	db := newMemStorage()
	db.captures["cap-1"] = &storage.CaptureRecord{
		ID: "cap-1", FilePath: "big.pcapng", LinkType: 1, ImportedAt: time.Now(),
	}
	db.packets["cap-1"] = []storage.PacketRecord{{
		CaptureID: "cap-1", No: 1, Time: first.Time,
		CapLen: first.CapLen, OrigLen: first.OrigLen, Offset: first.Offset,
	}}
	s := New(db, dir)

	// 前提：文件确实超过 fallback 的 64 MB 上限（否则不能证明走的是 seek）。
	fi, err := os.Stat(filepath.Join(dir, "big.pcapng"))
	if err != nil {
		t.Fatalf("stat big.pcapng: %v", err)
	}
	if fi.Size() <= maxDetailFileSize {
		t.Fatalf("测试文件大小 = %d, want > %d", fi.Size(), maxDetailFileSize)
	}

	detail, err := s.PacketDetail(context.Background(), "cap-1", 1)
	if err != nil {
		t.Fatalf("PacketDetail(seek): %v", err)
	}
	if detail.No != 1 {
		t.Errorf("No = %d, want 1", detail.No)
	}
	if detail.CapLen != first.CapLen {
		t.Errorf("CapLen = %d, want %d", detail.CapLen, first.CapLen)
	}
	if detail.LinkType != 1 {
		t.Errorf("LinkType = %d, want 1", detail.LinkType)
	}
	// 切出来的字节必须是真实的 Ethernet/IP/TCP/HTTP 包。
	names := map[string]bool{}
	for _, l := range detail.Layers {
		names[l.Name] = true
	}
	for _, want := range []string{"Frame", "Ethernet II", "Internet Protocol Version 4", "Transmission Control Protocol"} {
		if !names[want] {
			t.Errorf("缺少协议层 %q；实际=%v", want, layerNames(detail.Layers))
		}
	}
	if !strings.Contains(detail.PayloadText, "GET") {
		t.Errorf("PayloadText 未包含 GET: %q", detail.PayloadText)
	}
}

// TestDetail_OffsetFallback Offset=0 的旧数据退回全量解析（小文件仍能打开）。
func TestDetail_OffsetFallback(t *testing.T) {
	data, first := readSqliFirstPacket(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sqli.pcapng"), data, 0o644); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	db := newMemStorage()
	db.captures["cap-1"] = &storage.CaptureRecord{
		ID: "cap-1", FilePath: "sqli.pcapng", LinkType: 1, ImportedAt: time.Now(),
	}
	// 旧索引：Offset=0（故意把 CapLen 也写成异常小值，证明回退路径没有用索引）。
	db.packets["cap-1"] = []storage.PacketRecord{{
		CaptureID: "cap-1", No: 1, Time: first.Time, CapLen: 1, OrigLen: 1, Offset: 0,
	}}
	s := New(db, dir)

	detail, err := s.PacketDetail(context.Background(), "cap-1", 1)
	if err != nil {
		t.Fatalf("PacketDetail(fallback): %v", err)
	}
	if detail.CapLen != first.CapLen {
		t.Errorf("CapLen = %d, want %d（应来自全量解析，而非索引）", detail.CapLen, first.CapLen)
	}
	if !strings.Contains(detail.PayloadText, "GET") {
		t.Errorf("PayloadText 未包含 GET: %q", detail.PayloadText)
	}
}

// TestDetail_OffsetFallbackLargeFileStill413 无偏移索引时仍保留 64 MB 上限。
func TestDetail_OffsetFallbackLargeFileStill413(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big-noindex.bin")
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
	db.captures["cap-1"] = &storage.CaptureRecord{ID: "cap-1", FilePath: "big-noindex.bin"}
	db.packets["cap-1"] = []storage.PacketRecord{{CaptureID: "cap-1", No: 1, Offset: 0, CapLen: 100}}
	s := New(db, dir)

	_, err = s.PacketDetail(context.Background(), "cap-1", 1)
	if !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("err = %v, want ErrFileTooLarge", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/captures/cap-1/packets/1/detail", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413; body=%s", rec.Code, rec.Body.String())
	}
}

// TestDetail_CapLenTooLarge CapLen 超过 16 MB 的异常索引直接 413，且不读文件。
func TestDetail_CapLenTooLarge(t *testing.T) {
	dir := t.TempDir() // 文件根本不存在：必须在 Open 前就拒绝

	db := newMemStorage()
	db.captures["cap-1"] = &storage.CaptureRecord{ID: "cap-1", FilePath: "missing.bin", LinkType: 1}
	db.packets["cap-1"] = []storage.PacketRecord{{
		CaptureID: "cap-1", No: 1, Offset: 100, CapLen: maxDetailPacketSize + 1,
	}}
	s := New(db, dir)

	_, err := s.PacketDetail(context.Background(), "cap-1", 1)
	if !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("err = %v, want ErrFileTooLarge", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/captures/cap-1/packets/1/detail", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413; body=%s", rec.Code, rec.Body.String())
	}
}

// TestDetail_OffsetTruncated 偏移指向文件末尾之外 ⇒ 明确 500，不 panic。
func TestDetail_OffsetTruncated(t *testing.T) {
	data, first := readSqliFirstPacket(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "short.bin"), data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	db := newMemStorage()
	db.captures["cap-1"] = &storage.CaptureRecord{ID: "cap-1", FilePath: "short.bin", LinkType: 1}
	db.packets["cap-1"] = []storage.PacketRecord{{
		CaptureID: "cap-1", No: 1, Offset: len(data) + 16, CapLen: first.CapLen,
	}}
	s := New(db, dir)

	_, err := s.PacketDetail(context.Background(), "cap-1", 1)
	if err == nil {
		t.Fatal("偏移越界应返回错误")
	}
	if !strings.Contains(err.Error(), "偏移索引可能失效") {
		t.Errorf("err = %v, want 包含 '偏移索引可能失效'", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/captures/cap-1/packets/1/detail", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}
