package store

import (
	_ "embed"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// schemaSQL 内嵌建表语句（go:embed，保证代码与表结构版本一致）。
//
//go:embed schema.sql
var schemaSQL string

// nullableTime 将零值 time.Time 转为 nil（用于可空 timestamptz 插入）。
func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// isUniqueViolation 判断是否为 PostgreSQL 唯一约束冲突（SQLSTATE 23505）。
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
