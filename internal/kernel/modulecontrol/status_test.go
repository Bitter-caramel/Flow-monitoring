package modulecontrol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/eventbus"
	"flow-monitoring/internal/kernel/modulestatus"
	"flow-monitoring/internal/kernel/registry"
	"flow-monitoring/pkg/plugin"
)

// TestModuleViewIncludesStatusMetrics 验证收到 module.status 后，
// List() 的模块视图带 status.metrics（即 /api/modules 每项的结构）。
func TestModuleViewIncludesStatusMetrics(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "mod.a.json", registry.Descriptor{
		ID: "mod.a", Name: "甲", Version: "1.0.0", Layer: "L1",
	})

	bus := eventbus.New()
	defer bus.Close()
	store := modulestatus.New()
	store.Start(bus, plugin.StatusTopic)
	defer store.Stop()

	s, err := New(Options{ManifestDir: dir, Statuses: store})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	payload := `{"module_id":"mod.a","healthy":true,"message":"",` +
		`"metrics":{"packets_total":"7","runs_total":"2"},"at":"2024-01-02T03:04:05Z"}`
	if err := bus.Publish(plugin.StatusTopic, json.RawMessage(payload)); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := store.Get("mod.a"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("等待 mod.a 状态超时")
		}
		time.Sleep(5 * time.Millisecond)
	}

	views, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("List 长度 = %d, want 1", len(views))
	}
	v := views[0]
	if !v.Status.Healthy {
		t.Errorf("status.healthy = false, want true")
	}
	if v.Status.Metrics["packets_total"] != "7" || v.Status.Metrics["runs_total"] != "2" {
		t.Errorf("status.metrics = %v, want packets_total=7 runs_total=2", v.Status.Metrics)
	}

	// /api/modules 的 JSON 形状：status.metrics 必须真实出现在每一项里。
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(b), `"status":{`) ||
		!strings.Contains(string(b), `"packets_total":"7"`) {
		t.Fatalf("JSON 缺少 status.metrics: %s", b)
	}
}

// TestModuleViewStatusEmptyObject 验证没有状态时 status 是空对象（{}），不报错。
func TestModuleViewStatusEmptyObject(t *testing.T) {
	s := newTestService(t, registry.Descriptor{
		ID: "mod.a", Name: "甲", Version: "1.0.0", Layer: "L1",
	})
	views, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	b, err := json.Marshal(views[0])
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(b), `"status":{}`) {
		t.Fatalf("无状态时 status 应为 {}，实际: %s", b)
	}
}
