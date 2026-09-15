// Package logging 是平台的"记日志"工具底座。
//
// 设计依据：
//   - v3 流程梯队 1.2：「config + logging：工具底座，小而快」
//   - v0.3 架构第 7 章："能力探针优雅降级"——日志是降级的可观测出口
//   - 项目约束：协助者端运行后自动生成 logs 目录（含 program.log 等）
//
// 当前为最小可用版：
//   - 基于 Go 1.21+ 标准库 log/slog，零第三方依赖
//   - 多 sink：stdout + 文件（文件自动 MkdirAll，append 写）
//   - 自动加编号：每条日志带递增 "seq" 属性，便于追踪
//   - AddSource：DEBUG 级别自动加文件:行号
//   - 与 config 包无依赖：bootstrap 拆解 config.LogConfig 后传参
//
// 未实现（v3 梯队 5+）：
//   - 文件轮转（按 size/time）：MaxSize/MaxFiles 仅预留，未滚动
//   - 数据库 sink、远程 sink：v3 梯队 3+ 引入
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
)

// Level 等价于 slog.Level，提供包级别别名方便调用方少写一行 import。
type Level = slog.Level

// 标准级别常量（与 slog 一致）。
const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

// Logger 是带编号的日志器。
//
// 包装 *slog.Logger，使用方式与 slog 完全一致：
//
//	logger.Info("server started", "addr", cfg.HTTPAddr)
//	logger.Error("db connect failed", "err", err)
//
// 底层 seqHandler 通过 atomic.Uint64 共享同一计数器，
// 保证 WithAttrs/WithGroup 派生的子 logger 仍递增同一 seq。
type Logger struct {
	*slog.Logger
}

// New 创建 Logger。
//
// 参数：
//   - level: 最低日志级别（低于此级别不输出）
//   - format: "json" 或 "text"（其他值降级为 json）
//   - sinks: 多个 io.Writer 并行写入（stdout、文件、远程……）
//
// 设计要点（v3 梯队 1.2「带编号的日志」）：
// 自定义 seqHandler 包裹 slog.Handler，在每条 record 进入底层 handler 前
// 注入 "seq" 属性，保证全平台日志可按编号检索与排序。
func New(level Level, format string, sinks ...io.Writer) *Logger {
	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: level <= LevelDebug,
	}
	base := io.MultiWriter(sinks...)
	var lh slog.Handler
	if format == "text" {
		lh = slog.NewTextHandler(base, opts)
	} else {
		lh = slog.NewJSONHandler(base, opts)
	}
	seq := &atomic.Uint64{}
	return &Logger{Logger: slog.New(&seqHandler{lh: lh, seq: seq})}
}

// NewFromConfigFile 从配置参数创建 Logger 并打开文件 sink。
//
// 参数顺序与 config.LogConfig 字段一一对应；调用方负责关闭返回的 *os.File
// （通常在 bootstrap 的 shutdown 阶段 Close）。
func NewFromConfigFile(level Level, format, dir, fileName string) (*Logger, *os.File, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, fmt.Errorf("mkdir log dir %s: %w", dir, err)
	}
	fpath := filepath.Join(dir, fileName)
	f, err := os.OpenFile(fpath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("open log file %s: %w", fpath, err)
	}
	logger := New(level, format, os.Stdout, f)
	logger.Info("log file opened", "path", fpath)
	return logger, f, nil
}

// ParseLevel 解析字符串到 Level；空字符串或不识别均返回 LevelInfo。
func ParseLevel(s string) Level {
	switch s {
	case "DEBUG", "debug":
		return LevelDebug
	case "WARN", "warn":
		return LevelWarn
	case "ERROR", "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// seqHandler 给每条 record 自动附加递增编号 attr "seq"。
//
// 持有底层 slog.Handler 与共享的 atomic.Uint64 计数器；
// WithAttrs/WithGroup 派生新 seqHandler 时仍共享同一计数器，
// 保证派生 logger 与父 logger 的 seq 连续。
type seqHandler struct {
	lh  slog.Handler
	seq *atomic.Uint64
}

func (h *seqHandler) Enabled(ctx context.Context, l Level) bool {
	return h.lh.Enabled(ctx, l)
}

func (h *seqHandler) Handle(ctx context.Context, r slog.Record) error {
	r.AddAttrs(slog.Uint64("seq", h.seq.Add(1)))
	return h.lh.Handle(ctx, r)
}

func (h *seqHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &seqHandler{lh: h.lh.WithAttrs(attrs), seq: h.seq}
}

func (h *seqHandler) WithGroup(name string) slog.Handler {
	return &seqHandler{lh: h.lh.WithGroup(name), seq: h.seq}
}
