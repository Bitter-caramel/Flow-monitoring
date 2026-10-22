package pluginhost

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/config"
	"flow-monitoring/internal/kernel/eventbus"
	"flow-monitoring/internal/kernel/logging"
	"flow-monitoring/internal/kernel/storage"
	"flow-monitoring/pkg/plugin"
)

// fakeRunStorage 是 Bridge 测试用的存储替身：只实现可选 RunStore 扩展。
type fakeRunStorage struct {
	mu      sync.Mutex
	runs    []plugin.RunRecord
	listErr error
	saveErr error
}

var (
	_ storage.Storage = (*fakeRunStorage)(nil)
	_ runStoreDB      = (*fakeRunStorage)(nil)
)

func (s *fakeRunStorage) Captures() storage.CaptureStore { return nil }
func (s *fakeRunStorage) Packets() storage.PacketStore   { return nil }
func (s *fakeRunStorage) Close() error                   { return nil }

func (s *fakeRunStorage) RunSave(_ context.Context, rec plugin.RunRecord) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.runs {
		if s.runs[i].ID == rec.ID {
			s.runs[i] = rec
			return nil
		}
	}
	s.runs = append(s.runs, rec)
	return nil
}

func (s *fakeRunStorage) RunList(_ context.Context, limit int) ([]plugin.RunRecord, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]plugin.RunRecord(nil), s.runs...)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// TestBridgeRunStore 验证 Bridge 真的把 RunSave/RunList 落到存储实现上。
func TestBridgeRunStore(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()
	logger := logging.New(logging.LevelError, "text", io.Discard)
	db := &fakeRunStorage{}
	bridge := NewBridge(config.Default(), logger, bus, db)

	rs, ok := any(bridge).(plugin.RunStore)
	if !ok {
		t.Fatal("Bridge 未实现 plugin.RunStore")
	}

	started := time.Date(2024, 7, 1, 12, 0, 0, 0, time.UTC)
	rec := plugin.RunRecord{
		ID: "run-bridge-1", Mode: "static", Source: "replay:x",
		CaptureID: "cap-1", State: "running", Packets: 2, Alerts: 1, Started: started,
	}
	if err := rs.RunSave(rec); err != nil {
		t.Fatalf("Bridge.RunSave: %v", err)
	}
	got := rs.RunList(10)
	if len(got) != 1 || got[0].ID != rec.ID || got[0].CaptureID != rec.CaptureID {
		t.Fatalf("Bridge.RunList = %+v，期望单条 %+v", got, rec)
	}

	// 存储未实现可选扩展时：RunSave 明确报错，RunList 返回 nil。
	plainDB := &plainStorage{}
	bridge2 := NewBridge(config.Default(), logger, bus, plainDB)
	if err := bridge2.RunSave(rec); !errors.Is(err, plugin.ErrMissingDependency) {
		t.Errorf("无 RunStore 的存储 RunSave err = %v，期望 ErrMissingDependency", err)
	}
	if got := bridge2.RunList(10); got != nil {
		t.Errorf("无 RunStore 的存储 RunList = %+v，期望 nil", got)
	}

	// 数据库不可用：RunSave 如实报 ErrStorageUnavailable。
	bridge3 := NewBridge(config.Default(), logger, bus, nil)
	if err := bridge3.RunSave(rec); !errors.Is(err, plugin.ErrStorageUnavailable) {
		t.Errorf("db=nil 时 RunSave err = %v，期望 ErrStorageUnavailable", err)
	}
	if got := bridge3.RunList(10); got != nil {
		t.Errorf("db=nil 时 RunList = %+v，期望 nil", got)
	}
}

// plainStorage 只实现 storage.Storage，不提供 RunStore 扩展。
type plainStorage struct{}

func (s *plainStorage) Captures() storage.CaptureStore { return nil }
func (s *plainStorage) Packets() storage.PacketStore   { return nil }
func (s *plainStorage) Close() error                   { return nil }
