package collect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// indexPath 返回索引文件路径 <dir>/index.jsonl。
func (s *SegmentStore) indexPath() string {
	return filepath.Join(s.dir, segmentIndexFile)
}

// appendIndex 往 index.jsonl 追加一行 JSON（SegmentInfo）。
// 索引文件只在第一次追加时惰性创建；只追加、从不改写历史行。
func (s *SegmentStore) appendIndex(info SegmentInfo) error {
	if s.index == nil {
		f, err := os.OpenFile(s.indexPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("collect: open index: %w", err)
		}
		s.index = f
	}
	line, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("collect: marshal index line: %w", err)
	}
	line = append(line, '\n')
	if _, err := s.index.Write(line); err != nil {
		return fmt.Errorf("collect: append index line: %w", err)
	}
	return nil
}

// enforceRetention 从最老的段开始删，直到同时满足段数、总字节、保留小时三个限制。
// 值为 0（或负数）的项视为不限制。调用方必须已持有 s.mu。
func (s *SegmentStore) enforceRetention() error {
	if s.opts.RetentionSegments <= 0 && s.opts.RetentionBytes <= 0 && s.opts.RetentionHours <= 0 {
		return nil
	}

	var cutoff time.Time
	if s.opts.RetentionHours > 0 {
		cutoff = time.Now().Add(-time.Duration(s.opts.RetentionHours) * time.Hour)
	}

	for {
		idx := s.oldestLiveIndex()
		if idx < 0 {
			return nil
		}
		seg := s.sealed[idx]
		needDelete := false
		if s.opts.RetentionSegments > 0 && s.liveCount() > s.opts.RetentionSegments {
			needDelete = true
		}
		if !needDelete && s.opts.RetentionBytes > 0 && s.liveBytes() > s.opts.RetentionBytes {
			needDelete = true
		}
		if !needDelete && !cutoff.IsZero() && seg.StartTime.Before(cutoff) {
			needDelete = true
		}
		if !needDelete {
			return nil
		}
		if err := s.deleteSegment(idx); err != nil {
			return err
		}
	}
}

// oldestLiveIndex 返回最老（段号最小）的未删除段在 s.sealed 里的下标；没有则返回 -1。
func (s *SegmentStore) oldestLiveIndex() int {
	for i := range s.sealed {
		if !s.sealed[i].Deleted {
			return i
		}
	}
	return -1
}

// liveCount 返回未删除段的数量。
func (s *SegmentStore) liveCount() int {
	n := 0
	for i := range s.sealed {
		if !s.sealed[i].Deleted {
			n++
		}
	}
	return n
}

// liveBytes 返回未删除段的总字节数。
func (s *SegmentStore) liveBytes() int64 {
	var n int64
	for i := range s.sealed {
		if !s.sealed[i].Deleted {
			n += s.sealed[i].Bytes
		}
	}
	return n
}

// deleteSegment 删除一个段：删文件 + 追加一行 Deleted=true 的墓碑索引行。
// 调用方必须已持有 s.mu。
func (s *SegmentStore) deleteSegment(idx int) error {
	seg := s.sealed[idx]
	if seg.Deleted {
		return nil
	}
	path := filepath.Join(s.dir, seg.Name)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("collect: remove segment %s: %w", path, err)
	}
	seg.Deleted = true
	s.sealed[idx] = seg
	if err := s.appendIndex(seg); err != nil {
		return err
	}
	return nil
}
