package plugin

import (
	"net"
	"sync"
	"testing"
	"time"
)

// runStoreRPCHost 是 RPC 往返测试用的最小宿主桩。
//
// 通过嵌入 Host 接口满足 Host 方法集（测试只调用可选的 RunStore 方法，
// 其余方法不会被触发），避免为一条测试写完全部 Host 方法。
type runStoreRPCHost struct {
	Host

	mu   sync.Mutex
	runs []RunRecord
}

func (h *runStoreRPCHost) RunSave(rec RunRecord) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.runs {
		if h.runs[i].ID == rec.ID {
			h.runs[i] = rec
			return nil
		}
	}
	h.runs = append(h.runs, rec)
	return nil
}

func (h *runStoreRPCHost) RunList(limit int) []RunRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := append([]RunRecord(nil), h.runs...)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

var _ Host = (*runStoreRPCHost)(nil)
var _ RunStore = (*runStoreRPCHost)(nil)

// TestRunStoreRPC 验证 hostRPCClient 与 HostRPCServer 都实现了可选 RunStore，
// 且模块侧的类型断言能成功、调用会真正落到宿主实现上。
//
// ★ 这是 18a 的关键防回归点：Bridge/hostRPCClient 漏实现任意一个，
//
//	模块侧的类型断言就会失败而**静默不持久化**。
func TestRunStoreRPC(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	stub := &runStoreRPCHost{}
	go func() { _ = ServeHost(ln, stub) }()
	defer ln.Close()

	host, err := DialHost(ln.Addr().String())
	if err != nil {
		t.Fatalf("DialHost: %v", err)
	}
	if c, ok := host.(*hostRPCClient); ok {
		defer c.client.Close()
	}

	rs, ok := host.(RunStore)
	if !ok {
		t.Fatal("hostRPCClient 未实现 plugin.RunStore（模块侧会静默不持久化）")
	}

	started := time.Date(2024, 7, 1, 12, 0, 0, 0, time.UTC)
	rec := RunRecord{
		ID: "run-rpc-1", Mode: "static", Source: "replay:sqli",
		CaptureID: "cap-rpc", State: "running", Packets: 1, Alerts: 2,
		Started: started,
	}
	if err := rs.RunSave(rec); err != nil {
		t.Fatalf("RunSave via RPC: %v", err)
	}

	got := rs.RunList(10)
	if len(got) != 1 {
		t.Fatalf("RunList via RPC 返回 %d 条，期望 1（%+v）", len(got), got)
	}
	if got[0].ID != rec.ID || got[0].CaptureID != rec.CaptureID || got[0].State != rec.State ||
		got[0].Packets != rec.Packets || got[0].Alerts != rec.Alerts || !got[0].Started.Equal(rec.Started) {
		t.Errorf("RPC 往返字段不一致: got=%+v want=%+v", got[0], rec)
	}

	// UPSERT 语义经 RPC 也要成立。
	rec.State = "done"
	rec.Packets = 9
	rec.Finished = started.Add(time.Minute)
	if err := rs.RunSave(rec); err != nil {
		t.Fatalf("二次 RunSave via RPC: %v", err)
	}
	got = rs.RunList(10)
	if len(got) != 1 {
		t.Fatalf("UPSERT 后 RunList 返回 %d 条，期望 1（%+v）", len(got), got)
	}
	if got[0].State != "done" || got[0].Packets != 9 || !got[0].Finished.Equal(rec.Finished) {
		t.Errorf("RPC UPSERT 未更新字段: %+v", got[0])
	}
}
