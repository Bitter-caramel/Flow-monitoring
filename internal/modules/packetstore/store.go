// Package packetstore 是原始抓包文件的仓库（文件存储 + 索引编排）。
//
// 设计依据：
//   - v3 流程梯队 2.12："packet-store：抓包文件切成块存好，带索引，能快速找"
//   - 实施方案 2.0 第 6.2 节："原始包按'块文件 + 索引'保存"
//
// 职责分层：
//   - 原始字节 → 文件系统（本包管理，按 captureID 命名）
//   - 包元数据/索引 → storage.Storage（db-adapter 实现）
//   - 解析与解码 → 由调用方（importer）完成，本包不耦合 decoder
//
// 本包组合文件目录 + storage.Storage，提供"保存一个已解析的 capture"的编排能力。
package packetstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"flow-monitoring/internal/kernel/storage"
)

// Store 原始包文件仓库。
type Store struct {
	dir string           // 原始文件目录
	db  storage.Storage  // 索引存储
}

// New 创建 Store。
//
// dir 为原始文件目录（自动创建）；db 为索引存储（可为 nil，仅文件操作）。
func New(dir string, db storage.Storage) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("packetstore: mkdir %s: %w", dir, err)
	}
	return &Store{dir: dir, db: db}, nil
}

// SaveCapture 保存一个已解析的 capture。
//
// 流程：
//  1. 原始字节写入文件系统（dir/{id}.pcapng）
//  2. 计算 SHA-256
//  3. 元数据写入 storage.CaptureStore（若 db 非 nil）
//  4. 包元数据写入 storage.PacketStore（若 db 非 nil）
//
// packets 由调用方（importer）在解析+解码后转换为 storage.PacketRecord。
// 返回 CaptureRecord（含文件路径与 sha256）。
func (s *Store) SaveCapture(ctx context.Context, id, name string, raw []byte, packets []storage.PacketRecord) (*storage.CaptureRecord, error) {
	// 1. 存文件
	path, sha, err := s.saveFile(id, raw)
	if err != nil {
		return nil, err
	}

	rec := &storage.CaptureRecord{
		ID:          id,
		Name:        name,
		Format:      "pcapng",
		PacketCount: len(packets),
		ByteSize:    int64(len(raw)),
		FilePath:    path,
		SHA256:      sha,
		ImportedAt:  time.Now(),
	}

	// 首尾时间
	if len(packets) > 0 {
		rec.FirstSeen = packets[0].Time
		rec.LastSeen = packets[len(packets)-1].Time
	}

	// 2. 写索引
	if s.db != nil {
		if err := s.db.Captures().Create(ctx, rec); err != nil {
			_ = s.DeleteFile(path) // 回滚文件
			return nil, fmt.Errorf("packetstore: create capture index: %w", err)
		}
		if len(packets) > 0 {
			if err := s.db.Packets().SaveBatch(ctx, id, packets); err != nil {
				_ = s.db.Captures().Delete(ctx, id)
				_ = s.DeleteFile(path)
				return nil, fmt.Errorf("packetstore: save packet index: %w", err)
			}
		}
	}

	return rec, nil
}

// LoadCapture 从 DB 读取 capture 元数据。
func (s *Store) LoadCapture(ctx context.Context, id string) (*storage.CaptureRecord, error) {
	if s.db == nil {
		return nil, fmt.Errorf("packetstore: no db configured")
	}
	return s.db.Captures().Get(ctx, id)
}

// ReadRaw 读取原始文件字节。
func (s *Store) ReadRaw(filePath string) ([]byte, error) {
	if filePath == "" {
		return nil, fmt.Errorf("packetstore: empty file path")
	}
	// 防目录穿越：仅允许读取 dir 内的文件
	clean := filepath.Clean(filePath)
	dirClean := filepath.Clean(s.dir)
	if !filepath.IsAbs(clean) {
		clean = filepath.Join(s.dir, clean)
	}
	if !pathWithin(dirClean, clean) {
		return nil, fmt.Errorf("packetstore: file path outside store dir")
	}
	return os.ReadFile(clean)
}

// DeleteFile 删除原始文件。
func (s *Store) DeleteFile(filePath string) error {
	if filePath == "" {
		return nil
	}
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("packetstore: remove %s: %w", filePath, err)
	}
	return nil
}

// saveFile 写入原始字节到 dir/{id}.bin，返回相对路径与 SHA-256。
func (s *Store) saveFile(id string, raw []byte) (string, string, error) {
	if id == "" {
		return "", "", fmt.Errorf("packetstore: empty capture id")
	}
	filename := id + ".bin"
	fullPath := filepath.Join(s.dir, filename)

	// 写临时文件后原子重命名，避免半写
	tmp, err := os.CreateTemp(s.dir, "upload-*")
	if err != nil {
		return "", "", fmt.Errorf("packetstore: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // 清理残留

	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return "", "", fmt.Errorf("packetstore: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", "", err
	}
	if err := tmp.Close(); err != nil {
		return "", "", err
	}
	if err := os.Rename(tmpName, fullPath); err != nil {
		return "", "", fmt.Errorf("packetstore: rename: %w", err)
	}

	sum := sha256.Sum256(raw)
	return filename, hex.EncodeToString(sum[:]), nil
}

// pathWithin 判断 child 是否在 parent 目录内。
func pathWithin(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel != ".." && len(rel) > 0 && rel[0] != '.'
}
