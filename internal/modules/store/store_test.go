package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"flow-monitoring/internal/kernel/storage"
)

// TestNullableTime 零值转 nil，非零值原样返回。
func TestNullableTime(t *testing.T) {
	if nullableTime(time.Time{}) != nil {
		t.Error("zero time should map to nil")
	}
	now := time.Now()
	if nullableTime(now) != now {
		t.Error("non-zero time should be returned as-is")
	}
}

// TestIsUniqueViolation 唯一约束冲突识别。
func TestIsUniqueViolation(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "23505"}
	if !isUniqueViolation(pgErr) {
		t.Error("23505 should be unique violation")
	}
	if isUniqueViolation(errors.New("other")) {
		t.Error("ordinary error should not be unique violation")
	}
}

// testDSN 从环境变量读取测试用 PG DSN；未设置返回空。
func testDSN() string {
	return os.Getenv("FLOW_TEST_PG_DSN")
}

// TestPostgres_Integration 需要真实 PostgreSQL 的集成测试。
//
// 通过环境变量 FLOW_TEST_PG_DSN 提供连接串时运行，否则跳过。
// 运行方式（PowerShell）：
//
//	$env:FLOW_TEST_PG_DSN="postgres://user:pass@127.0.0.1:5432/test?sslmode=disable"
//	go test ./internal/modules/store -run TestPostgres_Integration -v
func TestPostgres_Integration(t *testing.T) {
	dsn := testDSN()
	if dsn == "" {
		t.Skip("FLOW_TEST_PG_DSN 未设置，跳过 PostgreSQL 集成测试")
	}

	ctx := context.Background()
	pg, err := New(ctx, dsn, 5)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer pg.Close()

	if err := pg.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// Capture CRUD
	rec := &storage.CaptureRecord{
		ID: "test-cap-1", Name: "integration", Format: "pcapng",
		LinkType: 1, PacketCount: 2, ImportedAt: time.Now(),
	}
	if err := pg.Captures().Create(ctx, rec); err != nil {
		t.Fatalf("Create capture: %v", err)
	}
	defer pg.Captures().Delete(ctx, rec.ID)

	got, err := pg.Captures().Get(ctx, rec.ID)
	if err != nil {
		t.Fatalf("Get capture: %v", err)
	}
	if got.Name != "integration" {
		t.Errorf("Name = %q, want integration", got.Name)
	}

	// Packet 批量写 + 分页读
	pkts := []storage.PacketRecord{
		{CaptureID: rec.ID, No: 1, Proto: "TCP", SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1000, DstPort: 80},
		{CaptureID: rec.ID, No: 2, Proto: "DNS", SrcIP: "1.1.1.1", DstIP: "8.8.8.8", SrcPort: 53, DstPort: 53},
	}
	if err := pg.Packets().SaveBatch(ctx, rec.ID, pkts); err != nil {
		t.Fatalf("SaveBatch: %v", err)
	}

	count, err := pg.Packets().Count(ctx, rec.ID)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 2 {
		t.Errorf("Count = %d, want 2", count)
	}

	res, err := pg.Packets().ListByCapture(ctx, rec.ID, storage.Page{Offset: 0, Limit: 10})
	if err != nil {
		t.Fatalf("ListByCapture: %v", err)
	}
	if len(res.Items) != 2 {
		t.Errorf("Items len = %d, want 2", len(res.Items))
	}
	if res.Items[0].Proto != "TCP" || res.Items[1].Proto != "DNS" {
		t.Errorf("proto order wrong: %+v", res.Items)
	}

	// 清理包
	if err := pg.Packets().DeleteByCapture(ctx, rec.ID); err != nil {
		t.Errorf("DeleteByCapture: %v", err)
	}
}
