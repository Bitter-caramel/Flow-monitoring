-- 流量分析平台 PostgreSQL 表结构（首版）。
-- 对应 storage-core 接口与实施方案 2.0 第 12.2 节核心表。

-- 抓包文件元数据
CREATE TABLE IF NOT EXISTS captures (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    format       TEXT NOT NULL,
    link_type    INTEGER NOT NULL,
    packet_count INTEGER NOT NULL DEFAULT 0,
    byte_size    BIGINT NOT NULL DEFAULT 0,
    file_path    TEXT NOT NULL DEFAULT '',
    sha256       TEXT NOT NULL DEFAULT '',
    first_seen   TIMESTAMPTZ,
    last_seen    TIMESTAMPTZ,
    imported_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 数据包元数据（不含原始字节，按 capture_id+no 唯一）
CREATE TABLE IF NOT EXISTS packets (
    capture_id TEXT NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
    no         INTEGER NOT NULL,
    time       TIMESTAMPTZ,
    src_ip     TEXT,
    dst_ip     TEXT,
    src_port   INTEGER,
    dst_port   INTEGER,
    proto      TEXT,
    info       TEXT,
    cap_len    INTEGER,
    orig_len   INTEGER,
    PRIMARY KEY (capture_id, no)
);

CREATE INDEX IF NOT EXISTS idx_packets_capture_no ON packets (capture_id, no);

-- 11-7b：按四元组双向查包（证据导出按连接取包）
CREATE INDEX IF NOT EXISTS idx_packets_endpoints
    ON packets (src_ip, src_port, dst_ip, dst_port);

-- 18a：分析任务（Run）持久化。服务重启后 /api/capture/runs 仍能看到历史。
-- finished 允许 NULL：仍在运行 / 重启恢复的 Run 没有结束时间（不写零年份）。
CREATE TABLE IF NOT EXISTS runs (
    id         TEXT PRIMARY KEY,
    mode       TEXT NOT NULL,
    source     TEXT NOT NULL DEFAULT '',
    capture_id TEXT NOT NULL DEFAULT '',
    state      TEXT NOT NULL,
    packets    INT  NOT NULL DEFAULT 0,
    alerts     INT  NOT NULL DEFAULT 0,
    err        TEXT NOT NULL DEFAULT '',
    started    TIMESTAMPTZ NOT NULL,
    finished   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_runs_started ON runs (started DESC);
