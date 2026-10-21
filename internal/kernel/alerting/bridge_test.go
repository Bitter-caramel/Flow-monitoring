package alerting

// 跨进程链路集成测试：capture 进程的告警经 pluginhost.Bridge.Publish 投到进程内总线。
// Bridge.Publish 会把 []byte 包成 json.RawMessage 再 Publish —— 与进程内直接
// Publish([]byte) 的动态类型不同。宿主 alerting 必须两种都能解，否则真实链路会全挂。

import (
	"io"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/config"
	"flow-monitoring/internal/kernel/eventbus"
	"flow-monitoring/internal/kernel/logging"
	"flow-monitoring/internal/kernel/pluginhost"
)

func TestServiceReceivesViaPluginBridge(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	svc := New(Config{Capacity: 100})
	svc.Start(bus, "detect.feature")
	defer svc.Stop()

	logger := logging.New(logging.LevelError, "text", io.Discard)
	bridge := pluginhost.NewBridge(config.Default(), logger, bus, nil)

	if err := bridge.Publish("detect.feature", alertJSON("bridge")); err != nil {
		t.Fatalf("bridge.Publish: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return svc.Stats().AlertsTotal == 1 })

	p := svc.Query(1, 10, 0, Filter{})
	if p.Total != 1 || p.Items[0].RuleID != "bridge" {
		t.Fatalf("query = %+v, want 单条 rule_id=bridge（跨进程桥接路径必须能解码）", p)
	}
	if st := svc.Stats(); st.DecodeErrors != 0 {
		t.Fatalf("decode_errors = %d, want 0", st.DecodeErrors)
	}
}
