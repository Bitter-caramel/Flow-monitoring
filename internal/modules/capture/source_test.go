package capture

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

// collectFrames 把数据源读空。
func collectFrames(t *testing.T, src Source) []Frame {
	t.Helper()
	var frames []Frame
	for {
		f, err := src.Next(context.Background())
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Next 失败: %v", err)
		}
		frames = append(frames, f)
	}
	return frames
}

// TestReplaySourceSQLi 验证 sqli 样本逐帧读出 1 帧、linkType=1、描述含文件名。
func TestReplaySourceSQLi(t *testing.T) {
	path := filepath.Join("..", "..", "..", "testdata", "attacks", "sqli.pcapng")
	src, err := NewReplaySource(path)
	if err != nil {
		t.Fatalf("NewReplaySource 失败: %v", err)
	}
	defer src.Close()

	frames := collectFrames(t, src)
	if got, want := len(frames), 1; got != want {
		t.Fatalf("帧数 = %d，期望 %d", got, want)
	}
	if got, want := frames[0].LinkType, 1; got != want {
		t.Errorf("linkType = %d，期望 %d", got, want)
	}
	if got := src.Describe(); !strings.Contains(got, "sqli.pcapng") {
		t.Errorf("Describe() = %q，期望包含文件名 sqli.pcapng", got)
	}
}

// TestReplaySourceNormal 验证 normal 样本逐帧读出 2 帧。
func TestReplaySourceNormal(t *testing.T) {
	path := filepath.Join("..", "..", "..", "testdata", "attacks", "normal.pcapng")
	src, err := NewReplaySource(path)
	if err != nil {
		t.Fatalf("NewReplaySource 失败: %v", err)
	}
	defer src.Close()

	frames := collectFrames(t, src)
	if got, want := len(frames), 2; got != want {
		t.Fatalf("帧数 = %d，期望 %d", got, want)
	}
	if got := src.Describe(); !strings.Contains(got, "normal.pcapng") {
		t.Errorf("Describe() = %q，期望包含文件名 normal.pcapng", got)
	}
}

// TestReplaySourceCloseIdempotent 验证 Close 幂等、关闭后 Next 返回 EOF。
func TestReplaySourceCloseIdempotent(t *testing.T) {
	path := filepath.Join("..", "..", "..", "testdata", "attacks", "sqli.pcapng")
	src, err := NewReplaySource(path)
	if err != nil {
		t.Fatalf("NewReplaySource 失败: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("首次 Close 失败: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("重复 Close 失败: %v", err)
	}
	if _, err := src.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("关闭后 Next err = %v，期望 io.EOF", err)
	}
}
