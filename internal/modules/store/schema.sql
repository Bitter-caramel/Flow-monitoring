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

-- C1：告警全量入库（单表全量，不做分表）。
-- ★ id 用 BIGSERIAL：库分配的 id 是唯一 ID，宿主内存环形缓冲回填同一个 id，
--   保证前端 since_id 增量拉取不会错乱。
-- ★ "offset" 是 SQL 保留字，必须加双引号，否则 CREATE/SELECT 都会语法错误。
CREATE TABLE IF NOT EXISTS alerts (
    id         BIGSERIAL PRIMARY KEY,
    rule_id    TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT '',
    severity   TEXT NOT NULL DEFAULT '',
    weight     INT  NOT NULL DEFAULT 0,
    time       TIMESTAMPTZ NOT NULL,
    src_ip     TEXT NOT NULL DEFAULT '',
    src_port   INT  NOT NULL DEFAULT 0,
    dst_ip     TEXT NOT NULL DEFAULT '',
    dst_port   INT  NOT NULL DEFAULT 0,
    proto      TEXT NOT NULL DEFAULT '',
    stream_id  INT  NOT NULL DEFAULT 0,
    pkt_no     INT  NOT NULL DEFAULT 0,
    buffer     TEXT NOT NULL DEFAULT '',
    "offset"   INT  NOT NULL DEFAULT 0,
    snippet    TEXT NOT NULL DEFAULT '',
    run_id     TEXT NOT NULL DEFAULT '',
    mode       TEXT NOT NULL DEFAULT '',
    capture_id TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_alerts_time       ON alerts (time DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_run        ON alerts (run_id, id);
CREATE INDEX IF NOT EXISTS idx_alerts_capture    ON alerts (capture_id, id);
CREATE INDEX IF NOT EXISTS idx_alerts_mode_time  ON alerts (mode, time DESC);
