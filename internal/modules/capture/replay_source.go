package capture

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/modules/parse/pcapng"
)

// ReplaySource 从磁盘上的 pcapng 文件回放数据帧。
//
// 启动时一次性读入并解析文件，把每一包连同解析后的链路类型缓存在内存中
// （样本都很小；大文件回放后续再引入流式读取）。
type ReplaySource struct {
	path   string
	frames []Frame

	mu     sync.Mutex
	idx    int
	closed bool
}

// NewReplaySource 读取并解析 path，构造可逐帧回放的数据源。
func NewReplaySource(path string) (*ReplaySource, error) {
	if path == "" {
		return nil, fmt.Errorf("capture: replay file is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("capture: read replay file %q: %w", path, err)
	}
	capture, err := pcapng.Parse(data, 0)
	if err != nil {
		return nil, fmt.Errorf("capture: parse replay file %q: %w", path, err)
	}

	frames := make([]Frame, 0, len(capture.Packets))
	for _, p := range capture.Packets {
		if p == nil {
			continue
		}
		frames = append(frames, Frame{
			Data:     p.Data,
			TS:       p.Time,
			LinkType: frameLinkType(capture, p.Iface),
		})
	}
	return &ReplaySource{path: path, frames: frames}, nil
}

// frameLinkType 与 cmd/parse-cli 的判定一致：优先按包所属接口取链路类型，
// 接口下标越界时回退到首接口，再回退到全局链路类型。
func frameLinkType(c *datamodel.Capture, iface int) int {
	if c == nil {
		return 0
	}
	if iface >= 0 && iface < len(c.Ifaces) {
		return c.Ifaces[iface].LinkType
	}
	if len(c.Ifaces) > 0 {
		return c.Ifaces[0].LinkType
	}
	return c.LinkType
}

// Next 返回下一帧；数据耗尽返回 io.EOF，上下文取消时返回 ctx.Err()。
func (s *ReplaySource) Next(ctx context.Context) (Frame, error) {
	if err := ctx.Err(); err != nil {
		return Frame{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.idx >= len(s.frames) {
		return Frame{}, io.EOF
	}
	f := s.frames[s.idx]
	s.idx++
	return f, nil
}

// Describe 返回数据源的人类可读描述。
func (s *ReplaySource) Describe() string {
	return "replay:" + filepath.Base(s.path)
}

// Close 释放缓存（幂等）。
func (s *ReplaySource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.frames = nil
	return nil
}
