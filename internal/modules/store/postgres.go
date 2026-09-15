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
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"flow-monitoring/internal/kernel/storage"
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

// captureStore CaptureStore 的 PostgreSQL 实现。
type captureStore struct{ p *Postgres }

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
	return &storage.PageResult[storage.CaptureRecord]{Items: items, Total: -1}, rows.Err()
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
