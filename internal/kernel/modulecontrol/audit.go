package modulecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// AuditMeta 是从 HTTP 控制面带进服务层的审计元数据。
//
// transport 层在请求通过 Token/CSRF 校验后把 Auth/Remote/Origin/RequestID
// 注入 context；modulecontrol 写审计时从这里取。CLI 等非 HTTP 入口可留空。
type AuditMeta struct {
	Remote    string // ip:port
	Auth      string // "token" 或 "none"
	Origin    string // Origin 请求头原文（可为空）
	RequestID string
}

// auditMetaKey 是 context 键类型（避免与其它包的键冲突）。
type auditMetaKey struct{}

// WithAuditMeta 把审计元数据写入 context。
func WithAuditMeta(ctx context.Context, meta AuditMeta) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, auditMetaKey{}, meta)
}

// AuditMetaFrom 从 context 读取审计元数据（无则返回零值）。
func AuditMetaFrom(ctx context.Context) AuditMeta {
	if ctx == nil {
		return AuditMeta{}
	}
	if v, ok := ctx.Value(auditMetaKey{}).(AuditMeta); ok {
		return v
	}
	return AuditMeta{}
}

// AuditRecord 是 logs/audit.jsonl 的一行（一行一条 JSON）。
//
// ★ 字段顺序按设计文档 §2.3 固定；★ 绝不包含 token 明文。
type AuditRecord struct {
	Time      string `json:"time"` // RFC3339
	Action    string `json:"action"`
	Module    string `json:"module"`
	DryRun    bool   `json:"dry_run"`
	Result    string `json:"result"` // ok | error
	Error     string `json:"error"`
	Remote    string `json:"remote"`
	Auth      string `json:"auth"` // token | none
	Origin    string `json:"origin"`
	RequestID string `json:"request_id"`
}

// AuditSink 是审计落地接口；nil = 不审计。
type AuditSink interface {
	Write(record AuditRecord) error
}

// FileAuditSink 把审计记录以 JSONL 追加写入文件（默认 logs/audit.jsonl）。
type FileAuditSink struct {
	path string
	mu   sync.Mutex
}

// NewFileAuditSink 创建文件审计 sink；路径为空或目录不可创建时返回错误。
func NewFileAuditSink(path string) (*FileAuditSink, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("modulecontrol: audit 路径为空")
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("modulecontrol: 创建审计目录 %s: %w", dir, err)
		}
	}
	return &FileAuditSink{path: path}, nil
}

// Write 追加一条 JSON 记录（自动补换行）。
func (f *FileAuditSink) Write(record AuditRecord) error {
	b, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("modulecontrol: 序列化审计记录: %w", err)
	}
	b = append(b, '\n')

	f.mu.Lock()
	defer f.mu.Unlock()

	file, err := os.OpenFile(f.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("modulecontrol: 打开审计文件 %s: %w", f.path, err)
	}
	if _, err := file.Write(b); err != nil {
		_ = file.Close()
		return fmt.Errorf("modulecontrol: 写审计文件 %s: %w", f.path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("modulecontrol: 关闭审计文件 %s: %w", f.path, err)
	}
	return nil
}

// WithAuditSink 注入审计实现（nil 允许 = 关闭审计）。
func (s *Service) WithAuditSink(sink AuditSink) *Service {
	s.audit = sink
	return s
}

// AuditDryRun 记录一次 dry-run（只返回影响面、不改清单/运行态）的审计。
//
// dry-run 不经过 SetEnabledCascade，因此由 transport 薄壳显式调用本方法；
// 审计失败只记 Warn，绝不影响主流程。
func (s *Service) AuditDryRun(ctx context.Context, id string, enabled bool, err error) {
	s.auditChange(ctx, id, enabled, true, err)
}

// auditChange 写一条 enable/disable 审计；sink 为 nil 时跳过。
func (s *Service) auditChange(ctx context.Context, id string, enabled, dryRun bool, opErr error) {
	if s.audit == nil {
		return
	}

	action := "module.disable"
	if enabled {
		action = "module.enable"
	}
	rec := AuditRecord{
		Time:   time.Now().Format(time.RFC3339),
		Action: action,
		Module: id,
		DryRun: dryRun,
		Result: "ok",
		Auth:   "none",
	}
	if opErr != nil {
		rec.Result = "error"
		rec.Error = opErr.Error()
	}

	meta := AuditMetaFrom(ctx)
	rec.Remote = meta.Remote
	rec.Origin = meta.Origin
	rec.RequestID = meta.RequestID
	if meta.Auth != "" {
		rec.Auth = meta.Auth
	}

	if err := s.audit.Write(rec); err != nil && s.logger != nil {
		// ★ 审计失败只告警，不影响主流程（禁停模块已经完成/已返回）。
		s.logger.Warn("modulecontrol: audit write failed", "err", err, "module", id, "action", action)
	}
}
