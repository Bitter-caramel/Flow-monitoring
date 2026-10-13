package alert

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// Sink 是告警的落点。
//
// 消费者只依赖这个接口：将来把消费者搬进独立插件进程时，
// 换一个"把告警经事件桥送回主进程"的实现即可，消费者代码不变。
type Sink interface {
	// Write 落一条告警。实现方应尽快使其可见（如 flush），便于 tail -f。
	Write(ev Event) error
	// Flush 把缓冲数据刷到底层存储。
	Flush() error
	// Close 关闭落点；必须幂等。
	Close() error
}

// FileSink 把告警按 JSON Lines 追加写到文件（一行一条，便于 grep/jq/tail -f）。
//
// 文件不存在则创建；已存在则追加，不截断、不覆盖。
// 写出的每条是单个 JSON 对象：没有数组包装、没有 BOM。
type FileSink struct {
	mu     sync.Mutex
	f      *os.File
	w      *bufio.Writer
	closed bool
}

// NewFileSink 追加打开 path（不存在则创建），返回 FileSink。
func NewFileSink(path string) (*FileSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("alert: open sink %s: %w", path, err)
	}
	return &FileSink{f: f, w: bufio.NewWriter(f)}, nil
}

// Write 写一行 JSON + '\n' 并立即 Flush，保证 tail -f 能马上看到。
func (s *FileSink) Write(ev Event) error {
	b, err := json.Marshal(ev) // 单条对象，无数组包装、无 BOM
	if err != nil {
		return fmt.Errorf("alert: marshal event: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("alert: sink closed")
	}
	if _, err := s.w.Write(b); err != nil {
		return fmt.Errorf("alert: write sink: %w", err)
	}
	if err := s.w.WriteByte('\n'); err != nil {
		return fmt.Errorf("alert: write sink: %w", err)
	}
	return s.flushLocked()
}

// Flush 把缓冲写回文件。
func (s *FileSink) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("alert: sink closed")
	}
	return s.flushLocked()
}

// flushLocked 刷新底层缓冲；调用方必须已持有 s.mu。
func (s *FileSink) flushLocked() error {
	if s.w == nil {
		return nil
	}
	if err := s.w.Flush(); err != nil {
		return fmt.Errorf("alert: flush sink: %w", err)
	}
	return nil
}

// Close 幂等：重复调用无副作用。
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true

	var firstErr error
	if s.w != nil {
		if err := s.w.Flush(); err != nil {
			firstErr = fmt.Errorf("alert: flush sink on close: %w", err)
		}
	}
	if s.f != nil {
		if err := s.f.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("alert: close sink: %w", err)
		}
	}
	return firstErr
}
