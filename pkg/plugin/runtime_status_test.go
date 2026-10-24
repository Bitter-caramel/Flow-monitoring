package plugin

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// statusFakeHost 是 plugin.Host 的最小桩：把每次 Publish 的载荷送进 pub 通道。
type statusFakeHost struct {
	mu   sync.Mutex
	pubs [][]byte
	pub  chan []byte
	logs []string
}

var _ Host = (*statusFakeHost)(nil)

func newStatusFakeHost() *statusFakeHost {
	return &statusFakeHost{pub: make(chan []byte, 128)}
}

func (h *statusFakeHost) Config() ConfigSnapshot { return ConfigSnapshot{} }
func (h *statusFakeHost) Log(level, msg string) {
	h.mu.Lock()
	h.logs = append(h.logs, level+"|"+msg)
	h.mu.Unlock()
}
func (h *statusFakeHost) Publish(topic string, data []byte) error {
	cp := append([]byte(nil), data...)
	h.mu.Lock()
	h.pubs = append(h.pubs, cp)
	h.mu.Unlock()
	select {
	case h.pub <- cp:
	default:
	}
	return nil
}
func (h *statusFakeHost) Poll(string, uint64, int) []EventRecord       { return nil }
func (h *statusFakeHost) RegisterHTTP(string, string, string) error    { return nil }
func (h *statusFakeHost) RegisterService(ServiceRef) error             { return nil }
func (h *statusFakeHost) LookupService(string) (ServiceRef, bool)      { return ServiceRef{}, false }
func (h *statusFakeHost) UnregisterService(string) error               { return nil }
func (h *statusFakeHost) CaptureCreate(CaptureRecord) error            { return nil }
func (h *statusFakeHost) CaptureGet(string) (CaptureRecord, bool)      { return CaptureRecord{}, false }
func (h *statusFakeHost) CaptureList(Page) CapturePage                 { return CapturePage{} }
func (h *statusFakeHost) CaptureDelete(string) error                   { return nil }
func (h *statusFakeHost) PacketSaveBatch(string, []PacketRecord) error { return nil }
func (h *statusFakeHost) PacketList(string, Page) PacketPage           { return PacketPage{} }
func (h *statusFakeHost) PacketCount(string) int                       { return 0 }
func (h *statusFakeHost) PacketDelete(string) error                    { return nil }

func (h *statusFakeHost) snapshot() [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([][]byte, len(h.pubs))
	copy(out, h.pubs)
	return out
}

// TestRuntimeStatusReporterPublishes 验证 Start 后按短周期发布 module.status，
// 且载荷包含 module_id / healthy / metrics（至少收到 2 条）。
func TestRuntimeStatusReporterPublishes(t *testing.T) {
	h := newStatusFakeHost()
	rt := &Runtime{
		Spec:           Manifest{ID: "modules.capture"},
		StatusInterval: 20 * time.Millisecond,
		OnHealth: func() HealthStatus {
			return HealthStatus{Healthy: true, Metrics: map[string]string{"packets_total": "7"}}
		},
		host: h,
	}
	rt.startStatusReporter()
	defer rt.stopStatusReporter()

	var got [][]byte
	deadline := time.After(2 * time.Second)
	for len(got) < 2 {
		select {
		case b := <-h.pub:
			got = append(got, b)
		case <-deadline:
			t.Fatalf("2s 内只收到 %d 条 module.status，期望 >=2", len(got))
		}
	}

	var rep StatusReport
	if err := json.Unmarshal(got[0], &rep); err != nil {
		t.Fatalf("解析状态载荷失败: %v; payload=%s", err, got[0])
	}
	if rep.ModuleID != "modules.capture" {
		t.Errorf("module_id = %q, want modules.capture", rep.ModuleID)
	}
	if !rep.Healthy {
		t.Errorf("healthy = false, want true")
	}
	if rep.Metrics["packets_total"] != "7" {
		t.Errorf("metrics.packets_total = %q, want 7", rep.Metrics["packets_total"])
	}
	if rep.At.IsZero() {
		t.Errorf("at 为空，期望上报时间")
	}
}

// TestRuntimeStatusReporterStops 验证 Stop 后不再发布。
func TestRuntimeStatusReporterStops(t *testing.T) {
	h := newStatusFakeHost()
	rt := &Runtime{
		Spec:           Manifest{ID: "modules.test"},
		StatusInterval: 20 * time.Millisecond,
		host:           h,
	}
	rt.startStatusReporter()

	// 至少先收到一条，证明上报已开始。
	select {
	case <-h.pub:
	case <-time.After(2 * time.Second):
		t.Fatal("2s 内未收到首条 module.status")
	}

	rt.stopStatusReporter()

	// 清掉停止前可能已在通道里的残留，再观察一个明显大于周期的窗口。
	for {
		select {
		case <-h.pub:
			continue
		default:
		}
		break
	}
	base := len(h.snapshot())
	time.Sleep(160 * time.Millisecond) // 8 个周期，足够暴露"停止后仍在发布"
	if n := len(h.snapshot()); n != base {
		t.Fatalf("Stop 后仍收到 %d 条新状态（停止前 %d 条）", n-base, base)
	}
}
