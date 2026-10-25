package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"flow-monitoring/internal/kernel/alerting"
	"flow-monitoring/internal/kernel/storage"
	"flow-monitoring/pkg/plugin"
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

// TestPostgres_ListByEndpoints_Integration 是 11-7b「按四元组双向查包」的**真库**测试。
//
// ★ 为什么必须有这一条：11-7b 落地时只用手写内存替身验证过语义，**这段 SQL 一次都没在真库跑过**。
// 内存替身能覆盖"双向/对称/排序/分页"的语义，但覆盖不了真库特有的行为 ——
// 参数类型（src_port 是 INTEGER 而 Endpoint.Port 是 uint16）、NULL 时间在 ORDER BY 里的位置、
// REFERENCES 外键、以及"跨 capture 查询"到底能不能查到别的 capture 的包。
//
// 通过 FLOW_TEST_PG_DSN 提供连接串时运行，否则跳过（与 TestPostgres_Integration 同一约定）。
func TestPostgres_ListByEndpoints_Integration(t *testing.T) {
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

	// ★ 走"能力探测"这条真实调用路径：PacketStore 里没有该方法，要断言成可选扩展。
	q, ok := pg.Packets().(storage.PacketFlowQuerier)
	if !ok {
		t.Fatal("PostgreSQL 实现未提供 storage.PacketFlowQuerier（可选扩展）")
	}

	// 每次运行用唯一 id，避免与上次残留数据相互干扰。
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	capA, capB := "it-a-"+suffix, "it-b-"+suffix
	base := time.Date(2024, 7, 1, 12, 0, 0, 0, time.UTC)
	for _, id := range []string{capA, capB} {
		if err := pg.Captures().Create(ctx, &storage.CaptureRecord{
			ID: id, Name: "listbyendpoints", Format: "pcapng", LinkType: 1, ImportedAt: time.Now(),
		}); err != nil {
			t.Fatalf("Create capture %s: %v", id, err)
		}
		defer pg.Captures().Delete(ctx, id) // packets 有 ON DELETE CASCADE
	}

	epA := storage.Endpoint{IP: "10.1.1.1", Port: 1111}
	epB := storage.Endpoint{IP: "10.1.1.2", Port: 80}

	// cap-a：A->B（t+2s）、B->A（t+1s）；cap-b：A->B（t+3s）；再加干扰包与"零时间"包。
	if err := pg.Packets().SaveBatch(ctx, capA, []storage.PacketRecord{
		{CaptureID: capA, No: 5, Time: base.Add(2 * time.Second), SrcIP: epA.IP, SrcPort: epA.Port, DstIP: epB.IP, DstPort: epB.Port, Proto: "TCP"},
		{CaptureID: capA, No: 1, Time: base.Add(1 * time.Second), SrcIP: epB.IP, SrcPort: epB.Port, DstIP: epA.IP, DstPort: epA.Port, Proto: "TCP"},
		{CaptureID: capA, No: 9, Time: base.Add(2 * time.Second), SrcIP: "10.1.1.9", SrcPort: 9999, DstIP: epB.IP, DstPort: epB.Port, Proto: "TCP"}, // 干扰：另一条连接
	}); err != nil {
		t.Fatalf("SaveBatch cap-a: %v", err)
	}
	if err := pg.Packets().SaveBatch(ctx, capB, []storage.PacketRecord{
		{CaptureID: capB, No: 3, Time: base.Add(3 * time.Second), SrcIP: epA.IP, SrcPort: epA.Port, DstIP: epB.IP, DstPort: epB.Port, Proto: "TLSv1.2"}, // ★ Proto 是展示名
		{CaptureID: capB, No: 4, Time: time.Time{}, SrcIP: epA.IP, SrcPort: epA.Port, DstIP: epB.IP, DstPort: epB.Port, Proto: "TCP"},                   // 零时间 => NULL
	}); err != nil {
		t.Fatalf("SaveBatch cap-b: %v", err)
	}

	got, err := q.ListByEndpoints(ctx, epA, epB, storage.Page{Limit: 100})
	if err != nil {
		t.Fatalf("ListByEndpoints: %v", err)
	}
	// ① 跨 capture + 双向 + 排除干扰包：应恰好 4 条（cap-a 两条 + cap-b 两条）。
	if len(got.Items) != 4 {
		t.Fatalf("Items len = %d, want 4（跨 capture + 双向 + 排除干扰）: %+v", len(got.Items), got.Items)
	}
	var sawAB, sawBA bool
	for _, it := range got.Items {
		if it.SrcIP == "10.1.1.9" {
			t.Errorf("干扰包（10.1.1.9）不应被返回: %+v", it)
		}
		if it.SrcIP == epA.IP {
			sawAB = true
		}
		if it.SrcIP == epB.IP {
			sawBA = true
		}
	}
	if !sawAB || !sawBA {
		t.Errorf("两个方向都应返回: ab=%v ba=%v", sawAB, sawBA)
	}

	// ② 排序按 (time, capture_id, no)：1s(cap-a/1)、2s(cap-a/5)、3s(cap-b/3)，NULL 时间排最后。
	want := []struct {
		capID string
		no    int
	}{{capA, 1}, {capA, 5}, {capB, 3}, {capB, 4}}
	for i, w := range want {
		if got.Items[i].CaptureID != w.capID || got.Items[i].No != w.no {
			t.Errorf("item[%d] = %s/%d, want %s/%d（★ 零时间应为 NULL 并排在最后）",
				i, got.Items[i].CaptureID, got.Items[i].No, w.capID, w.no)
		}
	}
	// ③ 每行都带自己的 capture_id（跨 capture 查询的关键）。
	if got.Items[0].CaptureID != capA || got.Items[2].CaptureID != capB {
		t.Errorf("capture_id 未按行返回: %+v", got.Items)
	}
	// ④ Total 沿用既有口径 -1（未统计）。
	if got.Total != -1 {
		t.Errorf("Total = %d, want -1（该实现不做统计）", got.Total)
	}

	// ⑤ 对称性：交换两端，结果必须一致。
	rev, err := q.ListByEndpoints(ctx, epB, epA, storage.Page{Limit: 100})
	if err != nil {
		t.Fatalf("reverse ListByEndpoints: %v", err)
	}
	if len(rev.Items) != len(got.Items) {
		t.Fatalf("reverse len = %d, want %d", len(rev.Items), len(got.Items))
	}
	for i := range rev.Items {
		if rev.Items[i] != got.Items[i] {
			t.Errorf("reverse item[%d] 不一致: %+v vs %+v", i, rev.Items[i], got.Items[i])
		}
	}

	// ⑥ 分页：Limit=1 只返回 1 条。
	one, err := q.ListByEndpoints(ctx, epA, epB, storage.Page{Limit: 1})
	if err != nil {
		t.Fatalf("ListByEndpoints limit=1: %v", err)
	}
	if len(one.Items) != 1 {
		t.Errorf("limit=1 len = %d, want 1", len(one.Items))
	}
	// ⑦ Offset 生效（取第 2 条）。
	second, err := q.ListByEndpoints(ctx, epA, epB, storage.Page{Offset: 1, Limit: 1})
	if err != nil {
		t.Fatalf("ListByEndpoints offset=1: %v", err)
	}
	if len(second.Items) != 1 || second.Items[0].No != want[1].no {
		t.Errorf("offset=1 => %+v, want no=%d", second.Items, want[1].no)
	}

	// ⑧ 查不存在的连接 => 空结果且无错误。
	none, err := q.ListByEndpoints(ctx,
		storage.Endpoint{IP: "192.0.2.1", Port: 1},
		storage.Endpoint{IP: "192.0.2.2", Port: 2},
		storage.Page{Limit: 10})
	if err != nil {
		t.Fatalf("不存在的连接应无错误: %v", err)
	}
	if len(none.Items) != 0 {
		t.Errorf("不存在的连接 Items len = %d, want 0", len(none.Items))
	}
}

// TestPostgres_RunSaveList_Integration 是 18a「Run 持久化」的真库测试。
//
// 覆盖：
//   - RunSave 后 RunList 能读回（含 capture_id / 计数 / 时间）；
//   - 同 id 二次保存走 UPSERT（不报错且字段被更新）；
//   - finished 零值写 NULL，读回仍是零值（不出现 0001 年份）；
//   - RunList 按 started DESC 排序。
//
// 通过 FLOW_TEST_PG_DSN 提供连接串时运行，否则跳过（与其它集成测试同一约定）。
func TestPostgres_RunSaveList_Integration(t *testing.T) {
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

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	idA, idB := "run-it-a-"+suffix, "run-it-b-"+suffix
	for _, id := range []string{idA, idB} {
		id := id
		defer func() { _, _ = pg.pool.Exec(context.Background(), `DELETE FROM runs WHERE id = $1`, id) }()
	}

	// A 用"很久以前"的 started；B 用"很久以后"的 started，保证排序断言稳定。
	startedA := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	startedB := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)

	recA := plugin.RunRecord{
		ID: idA, Mode: "static", Source: "replay:sqli", CaptureID: "cap-it-1",
		State: "running", Packets: 3, Alerts: 1, Started: startedA,
	}
	if err := pg.RunSave(ctx, recA); err != nil {
		t.Fatalf("首次 RunSave: %v", err)
	}

	findRun := func(list []plugin.RunRecord, id string) (plugin.RunRecord, bool) {
		for _, rec := range list {
			if rec.ID == id {
				return rec, true
			}
		}
		return plugin.RunRecord{}, false
	}

	gotAll, err := pg.RunList(ctx, 200)
	if err != nil {
		t.Fatalf("RunList: %v", err)
	}
	gotA, ok := findRun(gotAll, idA)
	if !ok {
		t.Fatalf("RunList 未读回 %s: %+v", idA, gotAll)
	}
	if gotA.Mode != recA.Mode || gotA.Source != recA.Source || gotA.CaptureID != recA.CaptureID ||
		gotA.State != recA.State || gotA.Packets != recA.Packets || gotA.Alerts != recA.Alerts {
		t.Errorf("读回字段不一致: got=%+v want=%+v", gotA, recA)
	}
	if !gotA.Finished.IsZero() {
		t.Errorf("finished 零值应写 NULL 并读回零值，实际: %s", gotA.Finished)
	}

	// UPSERT：同 id 二次保存必须更新字段，而不是报唯一冲突。
	finished := time.Date(2024, 7, 1, 12, 0, 0, 0, time.UTC)
	recA.State = "done"
	recA.Packets = 7
	recA.Alerts = 2
	recA.Finished = finished
	if err := pg.RunSave(ctx, recA); err != nil {
		t.Fatalf("二次 RunSave（UPSERT）: %v", err)
	}

	recB := plugin.RunRecord{
		ID: idB, Mode: "live", Source: "replay:normal", CaptureID: "",
		State: "error", Err: "boom", Packets: 1, Started: startedB,
	}
	if err := pg.RunSave(ctx, recB); err != nil {
		t.Fatalf("RunSave B: %v", err)
	}

	gotAll, err = pg.RunList(ctx, 200)
	if err != nil {
		t.Fatalf("二次 RunList: %v", err)
	}
	gotA, ok = findRun(gotAll, idA)
	if !ok {
		t.Fatalf("UPSERT 后 RunList 未找到 %s", idA)
	}
	if gotA.State != "done" || gotA.Packets != 7 || gotA.Alerts != 2 || !gotA.Finished.Equal(finished) {
		t.Errorf("UPSERT 未更新字段: %+v", gotA)
	}
	// 确认同 id 只有一条（UPSERT 而不是插入第二条）。
	countA := 0
	for _, rec := range gotAll {
		if rec.ID == idA {
			countA++
		}
	}
	if countA != 1 {
		t.Errorf("id=%s 在表中出现 %d 次，期望 1（UPSERT 覆盖）", idA, countA)
	}

	gotB, ok := findRun(gotAll, idB)
	if !ok {
		t.Fatalf("RunList 未读回 %s", idB)
	}
	if gotB.Err != "boom" || gotB.State != "error" {
		t.Errorf("Run B 字段不一致: %+v", gotB)
	}

	// 按 started DESC：B（2100）必须在 A（2000）之前。
	idxA, idxB := -1, -1
	for i, rec := range gotAll {
		switch rec.ID {
		case idA:
			idxA = i
		case idB:
			idxB = i
		}
	}
	if idxA < 0 || idxB < 0 || idxB >= idxA {
		t.Errorf("RunList 未按 started DESC 排序: idxA=%d idxB=%d list=%+v", idxA, idxB, gotAll)
	}
}

// TestPostgres_Alerts_Integration 是 C1「告警全量入库」的真库测试。
//
// 覆盖：
//   - InsertAlerts 的 INSERT ... RETURNING（id 递增、按输入顺序返回）；
//   - QueryAlerts 的分页（total 为过滤后条数、items 按 id 升序）；
//   - since_id 增量；
//   - 按 mode / run_id / capture_id 过滤；
//   - 空结果 items 为非 nil 空切片。
//
// 通过 FLOW_TEST_PG_DSN 提供连接串时运行，否则跳过（与其它集成测试同一约定）。
func TestPostgres_Alerts_Integration(t *testing.T) {
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

	// 每次运行用唯一 run_id/capture_id，避免与其它测试残留互相干扰。
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	runID := "it-alert-run-" + suffix
	capA := "it-alert-cap-a-" + suffix
	capB := "it-alert-cap-b-" + suffix

	defer func() {
		_, _ = pg.pool.Exec(context.Background(), `DELETE FROM alerts WHERE run_id = $1`, runID)
	}()

	base := time.Date(2024, 7, 1, 12, 0, 0, 0, time.UTC)
	inputs := []alerting.Alert{
		{
			RuleID: "rule-a", Name: "A", Severity: "high", Weight: 80,
			Time: base.Format(time.RFC3339), SrcIP: "10.0.0.1", SrcPort: 1111,
			DstIP: "10.0.0.2", DstPort: 80, Proto: "TCP", StreamID: 1, PktNo: 1,
			Buffer: "payload", Offset: 3, Snippet: "x",
			RunID: runID, Mode: alerting.ModeLive, CaptureID: capA,
		},
		{
			RuleID: "rule-b", Name: "B", Severity: "medium", Weight: 40,
			Time: base.Add(time.Second).Format(time.RFC3339), SrcIP: "10.0.0.3", SrcPort: 2222,
			DstIP: "10.0.0.4", DstPort: 443, Proto: "TLSv1.2", StreamID: 2, PktNo: 2,
			Buffer: "payload", Offset: 7, Snippet: "y",
			RunID: runID, Mode: alerting.ModeStatic, CaptureID: capB,
		},
		{
			RuleID: "rule-c", Name: "C", Severity: "low", Weight: 10,
			Time: base.Add(2 * time.Second).Format(time.RFC3339), SrcIP: "10.0.0.5", SrcPort: 3333,
			DstIP: "10.0.0.6", DstPort: 53, Proto: "DNS", StreamID: 3, PktNo: 3,
			Buffer: "payload", Offset: 0, Snippet: "z",
			RunID: runID, Mode: alerting.ModeLive, CaptureID: capB,
		},
	}

	// ① INSERT ... RETURNING：按输入顺序返回 id 且严格递增。
	ids, err := pg.InsertAlerts(ctx, inputs)
	if err != nil {
		t.Fatalf("InsertAlerts: %v", err)
	}
	if len(ids) != len(inputs) {
		t.Fatalf("返回 id 数量 = %d, want %d", len(ids), len(inputs))
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			t.Fatalf("id 未严格递增: %v", ids)
		}
	}

	// ② 分页：page=1 size=2 ⇒ 2 条，total 为过滤后总数 3（不是全表行数）。
	items, total, err := pg.QueryAlerts(ctx, alerting.AlertQuery{Page: 1, PageSize: 2, RunID: runID})
	if err != nil {
		t.Fatalf("QueryAlerts page1: %v", err)
	}
	if total != 3 {
		t.Fatalf("total = %d, want 3（过滤后总数）", total)
	}
	if len(items) != 2 || items[0].ID != ids[0] || items[1].ID != ids[1] {
		t.Fatalf("page1 items = %+v, want ids [%d %d]", items, ids[0], ids[1])
	}
	// 字段 round-trip（含 "offset" 保留字、端口、模式、时间）。
	if items[0].RuleID != "rule-a" || items[0].SrcPort != 1111 || items[0].Offset != 3 ||
		items[0].Mode != alerting.ModeLive || items[0].CaptureID != capA {
		t.Errorf("items[0] 字段 round-trip 错误: %+v", items[0])
	}
	if items[0].Time != base.Format(time.RFC3339) {
		t.Errorf("items[0].Time = %q, want %q", items[0].Time, base.Format(time.RFC3339))
	}

	// ③ 第二页：只剩 1 条（ids[2]）。
	items2, total2, err := pg.QueryAlerts(ctx, alerting.AlertQuery{Page: 2, PageSize: 2, RunID: runID})
	if err != nil {
		t.Fatalf("QueryAlerts page2: %v", err)
	}
	if total2 != 3 || len(items2) != 1 || items2[0].ID != ids[2] {
		t.Fatalf("page2 total=%d items=%+v, want total=3 单条 id=%d", total2, items2, ids[2])
	}

	// ④ since_id：id > ids[0] ⇒ 2 条（ids[1], ids[2]）。
	items3, total3, err := pg.QueryAlerts(ctx, alerting.AlertQuery{Page: 1, PageSize: 10, SinceID: ids[0], RunID: runID})
	if err != nil {
		t.Fatalf("QueryAlerts since_id: %v", err)
	}
	if total3 != 2 || len(items3) != 2 || items3[0].ID != ids[1] || items3[1].ID != ids[2] {
		t.Fatalf("since_id 增量错误: total=%d items=%+v", total3, items3)
	}

	// ⑤ 按 mode 过滤（叠加唯一 run 隔离）：static ⇒ 仅 rule-b。
	itemsM, totalM, err := pg.QueryAlerts(ctx, alerting.AlertQuery{
		Page: 1, PageSize: 10, RunID: runID, Mode: alerting.ModeStatic})
	if err != nil {
		t.Fatalf("QueryAlerts mode: %v", err)
	}
	if totalM != 1 || len(itemsM) != 1 || itemsM[0].ID != ids[1] {
		t.Fatalf("mode 过滤错误: total=%d items=%+v", totalM, itemsM)
	}

	// ⑥ 按 capture_id 过滤（叠加唯一 run 隔离）：capB ⇒ rule-b + rule-c（2 条）。
	itemsC, totalC, err := pg.QueryAlerts(ctx, alerting.AlertQuery{
		Page: 1, PageSize: 10, RunID: runID, CaptureID: capB})
	if err != nil {
		t.Fatalf("QueryAlerts capture: %v", err)
	}
	if totalC != 2 || len(itemsC) != 2 || itemsC[0].ID != ids[1] || itemsC[1].ID != ids[2] {
		t.Fatalf("capture_id 过滤错误: total=%d items=%+v", totalC, itemsC)
	}

	// ⑦ 空结果：items 必须是 non-nil 空切片，total 0。
	itemsNone, totalNone, err := pg.QueryAlerts(ctx, alerting.AlertQuery{
		Page: 1, PageSize: 10, RunID: "no-such-run-" + suffix})
	if err != nil {
		t.Fatalf("QueryAlerts 空结果: %v", err)
	}
	if totalNone != 0 || itemsNone == nil || len(itemsNone) != 0 {
		t.Fatalf("空结果异常: total=%d items=%#v（items 必须是 [] 不是 null）", totalNone, itemsNone)
	}
}
