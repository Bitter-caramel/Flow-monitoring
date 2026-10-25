// Package store 是存储接口的具体实现（PostgreSQL db-adapter）。
//
// 设计依据：
//   - v3 流程梯队 2.11："db-adapter：用 SQLite 真正能存能取（本项目改为 PostgreSQL）"
//   - 实施方案 2.0 第 6.2 节：PostgreSQL 16 为唯一数据库
//   - storage-core（internal/kernel/storage）定义接口，本包实现
//
// 本包提供：
//   - Postgres：基于 pgxpool 的 Storage 实现（captures / packets）
//   - schema.sql：建表语句（由 Migrate 执行，或手动导入）
//
// 连接方式：dsn 形如 "postgres://user:pass@host:5432/db?sslmode=disable"，
// 与 config.DBConfig.DSN 对应。
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"flow-monitoring/internal/kernel/alerting"
	"flow-monitoring/internal/kernel/storage"
	"flow-monitoring/pkg/plugin"
)

// Postgres 基于 PostgreSQL 的存储实现。
//
// 持有 pgxpool 连接池，实现 storage.Storage 接口。
type Postgres struct {
	pool *pgxpool.Pool
}

// New 创建 Postgres 存储并建立连接池。
//
// 参数：
//   - dsn：PostgreSQL 连接串
//   - maxConns：连接池上限（<=0 用 pgx 默认）
//
// 不自动建表；调用方在首次使用前调用 Migrate。
func New(ctx context.Context, dsn string, maxConns int) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parse dsn: %w", err)
	}
	if maxConns > 0 {
		cfg.MaxConns = int32(maxConns)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: create pool: %w", err)
	}
	// 探活：确保连接可用
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

// Migrate 建表（幂等）。
//
// schema 内嵌在代码中（go:embed），保证代码与表结构版本一致。
func (p *Postgres) Migrate(ctx context.Context) error {
	_, err := p.pool.Exec(ctx, schemaSQL)
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

// Captures 返回 CaptureStore 实现。
func (p *Postgres) Captures() storage.CaptureStore { return &captureStore{p} }

// Packets 返回 PacketStore 实现。
func (p *Postgres) Packets() storage.PacketStore { return &packetStore{p} }

// Close 关闭连接池。
func (p *Postgres) Close() error { p.pool.Close(); return nil }

// Ping 探测数据库连接是否仍可用（storage.Pinger 可选扩展）。
//
// bootstrap 的存储巡检每 10s 调用一次：可用 ⇒ Ping，失败 ⇒ 标记不可用并
// 关闭连接池，之后由巡检重新 Open + Migrate 实现自动恢复。
func (p *Postgres) Ping(ctx context.Context) error {
	if err := p.pool.Ping(ctx); err != nil {
		return fmt.Errorf("store: ping: %w", err)
	}
	return nil
}

// captureStore CaptureStore 的 PostgreSQL 实现。
type captureStore struct{ p *Postgres }

// 编译期断言：PG 实现提供可选计数能力与周期巡检需要的 Ping。
var (
	_ storage.CaptureCounter = (*captureStore)(nil)
	_ storage.Pinger         = (*Postgres)(nil)
)

func (s *captureStore) Create(ctx context.Context, rec *storage.CaptureRecord) error {
	_, err := s.p.pool.Exec(ctx, `
                INSERT INTO captures
                        (id, name, format, link_type, packet_count, byte_size, file_path, sha256, first_seen, last_seen, imported_at)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		rec.ID, rec.Name, rec.Format, rec.LinkType, rec.PacketCount,
		rec.ByteSize, rec.FilePath, rec.SHA256,
		nullableTime(rec.FirstSeen), nullableTime(rec.LastSeen), rec.ImportedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: capture %s", storage.ErrConflict, rec.ID)
		}
		return fmt.Errorf("store: create capture: %w", err)
	}
	return nil
}

func (s *captureStore) Get(ctx context.Context, id string) (*storage.CaptureRecord, error) {
	row := s.p.pool.QueryRow(ctx, `
                SELECT id, name, format, link_type, packet_count, byte_size, file_path, sha256, first_seen, last_seen, imported_at
                FROM captures WHERE id = $1`, id)

	var rec storage.CaptureRecord
	var firstSeen, lastSeen *time.Time
	if err := row.Scan(
		&rec.ID, &rec.Name, &rec.Format, &rec.LinkType, &rec.PacketCount,
		&rec.ByteSize, &rec.FilePath, &rec.SHA256, &firstSeen, &lastSeen, &rec.ImportedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("store: get capture: %w", err)
	}
	if firstSeen != nil {
		rec.FirstSeen = *firstSeen
	}
	if lastSeen != nil {
		rec.LastSeen = *lastSeen
	}
	return &rec, nil
}

func (s *captureStore) List(ctx context.Context, page storage.Page) (*storage.PageResult[storage.CaptureRecord], error) {
	// ★ 先统计真实总条数：此前固定返回 Total:-1，导致 DB 明明有数据时前端
	// 仍显示 total=-1（2026-10-17 现场实测）。这里不再使用 -1 哨兵。
	var total int
	if err := s.p.pool.QueryRow(ctx, `SELECT count(*) FROM captures`).Scan(&total); err != nil {
		return nil, fmt.Errorf("store: count captures: %w", err)
	}

	rows, err := s.p.pool.Query(ctx, `
                SELECT id, name, format, link_type, packet_count, byte_size, file_path, sha256, first_seen, last_seen, imported_at
                FROM captures ORDER BY imported_at DESC LIMIT $1 OFFSET $2`,
		page.Limit, page.Offset,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list captures: %w", err)
	}
	defer rows.Close()

	var items []storage.CaptureRecord
	for rows.Next() {
		var rec storage.CaptureRecord
		var firstSeen, lastSeen *time.Time
		if err := rows.Scan(
			&rec.ID, &rec.Name, &rec.Format, &rec.LinkType, &rec.PacketCount,
			&rec.ByteSize, &rec.FilePath, &rec.SHA256, &firstSeen, &lastSeen, &rec.ImportedAt,
		); err != nil {
			return nil, fmt.Errorf("store: scan capture: %w", err)
		}
		if firstSeen != nil {
			rec.FirstSeen = *firstSeen
		}
		if lastSeen != nil {
			rec.LastSeen = *lastSeen
		}
		items = append(items, rec)
	}
	return &storage.PageResult[storage.CaptureRecord]{Items: items, Total: total}, rows.Err()
}

// Count 返回 capture 真实总条数（storage.CaptureCounter 可选扩展）。
//
// List 本身已经带真实 Total；本方法用于调用方只关心条数、或分页实现
// 仍返回未统计哨兵时的兜底。
func (s *captureStore) Count(ctx context.Context) (int, error) {
	var n int
	if err := s.p.pool.QueryRow(ctx, `SELECT count(*) FROM captures`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count captures: %w", err)
	}
	return n, nil
}

func (s *captureStore) Delete(ctx context.Context, id string) error {
	tag, err := s.p.pool.Exec(ctx, `DELETE FROM captures WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: delete capture: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// packetStore PacketStore 的 PostgreSQL 实现。
type packetStore struct{ p *Postgres }

// ★ 编译期断言：PG 实现必须提供「按连接（四元组双向）查包」这个**可选扩展**
// （storage.PacketFlowQuerier）。它故意不并进 storage.PacketStore —— 那样会连带
// 要求插件侧 RPC 适配器与若干测试替身都实现，并牵动跨进程 RPC 协议。
var _ storage.PacketFlowQuerier = (*packetStore)(nil)

func (s *packetStore) SaveBatch(ctx context.Context, captureID string, packets []storage.PacketRecord) error {
	if len(packets) == 0 {
		return nil
	}
	// 批量插入（使用 CopyFrom 提升大文件导入性能）
	rows := make([][]any, 0, len(packets))
	for _, pk := range packets {
		rows = append(rows, []any{
			captureID, pk.No, nullableTime(pk.Time), pk.SrcIP, pk.DstIP,
			int(pk.SrcPort), int(pk.DstPort), pk.Proto, pk.Info, pk.CapLen, pk.OrigLen,
		})
	}
	_, err := s.p.pool.CopyFrom(ctx,
		pgx.Identifier{"packets"},
		[]string{"capture_id", "no", "time", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "info", "cap_len", "orig_len"},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return fmt.Errorf("store: save packets: %w", err)
	}
	return nil
}

func (s *packetStore) ListByCapture(ctx context.Context, captureID string, page storage.Page) (*storage.PageResult[storage.PacketRecord], error) {
	rows, err := s.p.pool.Query(ctx, `
                SELECT no, time, src_ip, dst_ip, src_port, dst_port, proto, info, cap_len, orig_len
                FROM packets WHERE capture_id = $1 ORDER BY no ASC LIMIT $2 OFFSET $3`,
		captureID, page.Limit, page.Offset,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list packets: %w", err)
	}
	defer rows.Close()

	var items []storage.PacketRecord
	for rows.Next() {
		var pk storage.PacketRecord
		var ts *time.Time
		if err := rows.Scan(
			&pk.No, &ts, &pk.SrcIP, &pk.DstIP, &pk.SrcPort, &pk.DstPort,
			&pk.Proto, &pk.Info, &pk.CapLen, &pk.OrigLen,
		); err != nil {
			return nil, fmt.Errorf("store: scan packet: %w", err)
		}
		pk.CaptureID = captureID
		if ts != nil {
			pk.Time = *ts
		}
		items = append(items, pk)
	}
	return &storage.PageResult[storage.PacketRecord]{Items: items, Total: -1}, rows.Err()
}

func (s *packetStore) ListByEndpoints(ctx context.Context, ep1, ep2 storage.Endpoint, page storage.Page) (*storage.PageResult[storage.PacketRecord], error) {
	rows, err := s.p.pool.Query(ctx, `
                SELECT capture_id, no, time, src_ip, dst_ip, src_port, dst_port, proto, info, cap_len, orig_len
                FROM packets
                WHERE (src_ip = $1 AND src_port = $2 AND dst_ip = $3 AND dst_port = $4)
                   OR (src_ip = $3 AND src_port = $4 AND dst_ip = $1 AND dst_port = $2)
                ORDER BY time ASC, capture_id ASC, no ASC LIMIT $5 OFFSET $6`,
		ep1.IP, int(ep1.Port), ep2.IP, int(ep2.Port), page.Limit, page.Offset,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list packets by endpoints: %w", err)
	}
	defer rows.Close()

	var items []storage.PacketRecord
	for rows.Next() {
		var pk storage.PacketRecord
		var ts *time.Time
		if err := rows.Scan(
			&pk.CaptureID, &pk.No, &ts, &pk.SrcIP, &pk.DstIP, &pk.SrcPort, &pk.DstPort,
			&pk.Proto, &pk.Info, &pk.CapLen, &pk.OrigLen,
		); err != nil {
			return nil, fmt.Errorf("store: scan packet: %w", err)
		}
		if ts != nil {
			pk.Time = *ts
		}
		items = append(items, pk)
	}
	return &storage.PageResult[storage.PacketRecord]{Items: items, Total: -1}, rows.Err()
}

func (s *packetStore) Count(ctx context.Context, captureID string) (int, error) {
	var n int
	if err := s.p.pool.QueryRow(ctx, `SELECT count(*) FROM packets WHERE capture_id = $1`, captureID).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count packets: %w", err)
	}
	return n, nil
}

func (s *packetStore) DeleteByCapture(ctx context.Context, captureID string) error {
	_, err := s.p.pool.Exec(ctx, `DELETE FROM packets WHERE capture_id = $1`, captureID)
	if err != nil {
		return fmt.Errorf("store: delete packets: %w", err)
	}
	return nil
}

// —— 18a：分析任务（Run）持久化 ——
//
// 不作为 storage.Storage 的必选方法：只有宿主 Bridge 需要（模块侧经可选
// plugin.RunStore 调用），避免牵连所有存储替身与跨进程适配器。
// 由 bridge.go 的 runStoreDB 做结构化断言。

// RunSave 以 UPSERT 语义保存一条 Run 记录（同 id 二次保存更新字段）。
//
// finished 为零值时写 NULL：仍在运行 / 重启恢复的 Run 没有结束时间，
// 不应写入零年份（否则前端会显示 0001-01-01）。
func (p *Postgres) RunSave(ctx context.Context, rec plugin.RunRecord) error {
	_, err := p.pool.Exec(ctx, `
                INSERT INTO runs
                        (id, mode, source, capture_id, state, packets, alerts, err, started, finished)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                ON CONFLICT (id) DO UPDATE SET
                        mode       = EXCLUDED.mode,
                        source     = EXCLUDED.source,
                        capture_id = EXCLUDED.capture_id,
                        state      = EXCLUDED.state,
                        packets    = EXCLUDED.packets,
                        alerts     = EXCLUDED.alerts,
                        err        = EXCLUDED.err,
                        started    = EXCLUDED.started,
                        finished   = EXCLUDED.finished`,
		rec.ID, rec.Mode, rec.Source, rec.CaptureID, rec.State,
		rec.Packets, rec.Alerts, rec.Err, rec.Started, nullableTime(rec.Finished),
	)
	if err != nil {
		return fmt.Errorf("store: save run: %w", err)
	}
	return nil
}

// RunList 按 started DESC 返回最近 limit 条 Run 记录。
//
// limit <= 0 时使用默认值 200（与 capture 模块回填上限保持一致）。
func (p *Postgres) RunList(ctx context.Context, limit int) ([]plugin.RunRecord, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := p.pool.Query(ctx, `
                SELECT id, mode, source, capture_id, state, packets, alerts, err, started, finished
                FROM runs ORDER BY started DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list runs: %w", err)
	}
	defer rows.Close()

	var items []plugin.RunRecord
	for rows.Next() {
		var rec plugin.RunRecord
		var finished *time.Time
		if err := rows.Scan(
			&rec.ID, &rec.Mode, &rec.Source, &rec.CaptureID, &rec.State,
			&rec.Packets, &rec.Alerts, &rec.Err, &rec.Started, &finished,
		); err != nil {
			return nil, fmt.Errorf("store: scan run: %w", err)
		}
		if finished != nil {
			rec.Finished = *finished
		}
		items = append(items, rec)
	}
	return items, rows.Err()
}

// —— 任务 C1：告警全量入库（单表全量） ——
//
// 这两个方法让 *Postgres 满足 alerting.AlertStore（消费者侧定义的接口）。
// 不做成分表（D0 才做），只做单表全量 + 批量写 + 查库。

// alertColumns 是 alerts 表的读取列（顺序与 scanAlertRow 一一对应）。
//
// ★ "offset" 是 SQL 保留字，必须加双引号。
const alertColumns = `id, rule_id, name, severity, weight, time, src_ip, src_port, dst_ip, dst_port, proto, stream_id, pkt_no, buffer, "offset", snippet, run_id, mode, capture_id`

// 编译期断言：*Postgres 满足 alerting 的告警持久化契约（AlertStore）。
//
// ★ 界面定义在 alerting（消费者侧），store 作为实现方在此声明，改动签名会立刻编译失败。
var _ alerting.AlertStore = (*Postgres)(nil)

// alertTimeValue 把告警的 RFC3339 字符串转成 time.Time（供 timestamptz 写入）。
//
// ★ time 列 NOT NULL：解析失败时退回当前时间，保证不因个别坏值整批失败。
func alertTimeValue(s string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	return time.Now().UTC()
}

// InsertAlerts 批量插入告警，按输入顺序返回库分配的 BIGSERIAL id。
//
// ★ 必须是单条 INSERT ... RETURNING：失败时一行都不会插入，上层重试不会重复。
// ★ 多行 VALUES 保证 RETURNING 顺序与输入顺序一致（每行 18 个占位符，200 行也远低于参数上限）。
func (p *Postgres) InsertAlerts(ctx context.Context, alerts []alerting.Alert) ([]uint64, error) {
	if len(alerts) == 0 {
		return nil, nil
	}

	const colsPerRow = 18
	var sb strings.Builder
	sb.WriteString(`INSERT INTO alerts (rule_id, name, severity, weight, time, src_ip, src_port, dst_ip, dst_port, proto, stream_id, pkt_no, buffer, "offset", snippet, run_id, mode, capture_id) VALUES `)
	args := make([]any, 0, len(alerts)*colsPerRow)
	for i, a := range alerts {
		if i > 0 {
			sb.WriteByte(',')
		}
		base := i * colsPerRow
		sb.WriteByte('(')
		for j := 0; j < colsPerRow; j++ {
			if j > 0 {
				sb.WriteByte(',')
			}
			fmt.Fprintf(&sb, "$%d", base+j+1)
		}
		sb.WriteByte(')')
		args = append(args,
			a.RuleID, a.Name, a.Severity, a.Weight, alertTimeValue(a.Time),
			a.SrcIP, int(a.SrcPort), a.DstIP, int(a.DstPort), a.Proto,
			a.StreamID, a.PktNo, a.Buffer, a.Offset, a.Snippet,
			a.RunID, a.Mode, a.CaptureID,
		)
	}
	sb.WriteString(` RETURNING id`)

	rows, err := p.pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("store: insert alerts: %w", err)
	}
	defer rows.Close()

	ids := make([]uint64, 0, len(alerts))
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: scan alert id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: insert alerts rows: %w", err)
	}
	if len(ids) != len(alerts) {
		return ids, fmt.Errorf("store: insert alerts 返回 id 数量 %d != 告警数量 %d", len(ids), len(alerts))
	}
	return ids, nil
}

// QueryAlerts 按过滤条件分页查询告警（ORDER BY id ASC），返回 items 与过滤后总数。
//
// ★ total 是「经过 since_id + mode/run_id/capture_id 过滤后的总数」，不是全表行数。
// ★ items 永远是 non-nil 切片（空结果返回 []，避免 JSON 序列化成 null）。
func (p *Postgres) QueryAlerts(ctx context.Context, q alerting.AlertQuery) ([]alerting.Alert, int, error) {
	var conds []string
	var args []any
	addCond := func(expr string, v any) {
		args = append(args, v)
		conds = append(conds, fmt.Sprintf(expr, len(args)))
	}
	if q.SinceID > 0 {
		addCond("id > $%d", int64(q.SinceID))
	}
	if q.Mode != "" {
		addCond("mode = $%d", q.Mode)
	}
	if q.RunID != "" {
		addCond("run_id = $%d", q.RunID)
	}
	if q.CaptureID != "" {
		addCond("capture_id = $%d", q.CaptureID)
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	var total int
	if err := p.pool.QueryRow(ctx, "SELECT count(*) FROM alerts"+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: count alerts: %w", err)
	}

	page, pageSize := q.Page, q.PageSize
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = alerting.DefaultPageSize
	}
	if pageSize > alerting.MaxPageSize {
		pageSize = alerting.MaxPageSize
	}
	offset := (page - 1) * pageSize

	pageArgs := append(append([]any{}, args...), pageSize, offset)
	limitPh := len(args) + 1
	offsetPh := len(args) + 2
	sql := "SELECT " + alertColumns + " FROM alerts" + where +
		fmt.Sprintf(" ORDER BY id ASC LIMIT $%d OFFSET $%d", limitPh, offsetPh)

	rows, err := p.pool.Query(ctx, sql, pageArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("store: query alerts: %w", err)
	}
	defer rows.Close()

	items := make([]alerting.Alert, 0, pageSize)
	for rows.Next() {
		a, err := scanAlertRow(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, a)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("store: query alerts rows: %w", err)
	}
	return items, total, nil
}

// scanAlertRow 把一行 alerts 读进 alerting.Alert（time 统一格式化为 UTC RFC3339Nano）。
func scanAlertRow(rows pgx.Rows) (alerting.Alert, error) {
	var a alerting.Alert
	var ts time.Time
	var srcPort, dstPort int
	if err := rows.Scan(
		&a.ID, &a.RuleID, &a.Name, &a.Severity, &a.Weight, &ts,
		&a.SrcIP, &srcPort, &a.DstIP, &dstPort, &a.Proto,
		&a.StreamID, &a.PktNo, &a.Buffer, &a.Offset, &a.Snippet,
		&a.RunID, &a.Mode, &a.CaptureID,
	); err != nil {
		return alerting.Alert{}, fmt.Errorf("store: scan alert: %w", err)
	}
	a.SrcPort = uint16(srcPort)
	a.DstPort = uint16(dstPort)
	a.Time = ts.UTC().Format(time.RFC3339Nano)
	return a, nil
}
