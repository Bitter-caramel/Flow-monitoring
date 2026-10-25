package capture

import (
	"testing"
	"time"

	"flow-monitoring/pkg/plugin"
	"flow-monitoring/pkg/plugintest"
)

// newRunHost 构造支持 Run 持久化的假宿主（RunHost 额外实现 plugin.RunStore）。
func newRunHost(cfg plugin.ConfigSnapshot, restore ...plugin.RunRecord) *plugintest.RunHost {
	h := plugintest.NewRunHost(restore...)
	h.Cfg = cfg
	return h
}

// TestRunPersistsOnCreateAndFinish 验证：
//   - addRun 后立即 RunSave 一次，state=running、capture_id 正确；
//   - finishRun 后再 RunSave 一次，state=done、packets/alerts/finished 正确。
func TestRunPersistsOnCreateAndFinish(t *testing.T) {
	cfg := staticTestConfig(t)
	host := newRunHost(cfg)
	m := &captureModule{}
	if err := m.start(host, cfg); err != nil {
		t.Fatalf("start 失败: %v", err)
	}
	t.Cleanup(func() { _ = m.stop() })

	// 阻塞数据源：保证 addRun 返回时 Run 仍处于 running，不会与 finish 抢跑。
	run, err := m.addRun(modeStatic, "test:blocking", "cap-persist", &blockingSource{unblock: make(chan struct{})})
	if err != nil {
		t.Fatalf("addRun 失败: %v", err)
	}

	saved := host.Saved()
	if len(saved) != 1 {
		t.Fatalf("addRun 后 RunSave 次数 = %d，期望 1（%+v）", len(saved), saved)
	}
	if saved[0].ID != run.ID {
		t.Errorf("持久化 ID = %q，期望 %q", saved[0].ID, run.ID)
	}
	if saved[0].State != runStateRunning {
		t.Errorf("addRun 持久化 state = %q，期望 running", saved[0].State)
	}
	if saved[0].CaptureID != "cap-persist" {
		t.Errorf("持久化 capture_id = %q，期望 cap-persist", saved[0].CaptureID)
	}

	// 直接落定并检查第二次保存（阻塞源仍在跑，不会产生并发写）。
	m.finishRun(run, runStateDone, "", 12, 5, 0)

	saved = host.Saved()
	if len(saved) != 2 {
		t.Fatalf("finishRun 后 RunSave 次数 = %d，期望 2（%+v）", len(saved), saved)
	}
	last := saved[1]
	if last.State != runStateDone {
		t.Errorf("finishRun 持久化 state = %q，期望 done", last.State)
	}
	if last.Packets != 12 || last.Alerts != 5 {
		t.Errorf("finishRun 持久化 packets/alerts = %d/%d，期望 12/5", last.Packets, last.Alerts)
	}
	if last.Finished.IsZero() {
		t.Error("finishRun 持久化 finished 仍为零值，期望落定时间")
	}
	if last.CaptureID != "cap-persist" {
		t.Errorf("finishRun 持久化 capture_id = %q，期望 cap-persist", last.CaptureID)
	}
}

// TestStartRestoresHistoryAndHealsZombieRunning 验证：
//   - start() 从 RunStore 回填历史；
//   - 上次进程遗留的 running 记录被改为 error，Err 明确；
//   - 回填记录不创建 goroutine、不重建 hotpath。
func TestStartRestoresHistoryAndHealsZombieRunning(t *testing.T) {
	cfg := staticTestConfig(t)
	started := time.Date(2024, 7, 1, 12, 0, 0, 0, time.UTC)
	host := newRunHost(cfg,
		plugin.RunRecord{
			ID: "run-zombie", Mode: modeStatic, Source: "replay:sqli",
			CaptureID: "cap-old", State: runStateRunning, Packets: 9, Alerts: 2,
			Started: started,
		},
		plugin.RunRecord{
			ID: "run-done", Mode: modeStatic, Source: "replay:normal",
			CaptureID: "cap-done", State: runStateDone, Packets: 4, Alerts: 1,
			Started: started.Add(-time.Hour), Finished: started,
		},
	)
	m := &captureModule{}
	if err := m.start(host, cfg); err != nil {
		t.Fatalf("start 失败: %v", err)
	}
	t.Cleanup(func() { _ = m.stop() })

	v, ok := m.getRun("run-zombie")
	if !ok {
		t.Fatal("回填后内存中找不到 run-zombie")
	}
	if v.State != runStateError {
		t.Errorf("僵尸 running 回填后 state = %q，期望 error", v.State)
	}
	if v.Err != zombieRunErr {
		t.Errorf("僵尸 running 回填后 Err = %q，期望 %q", v.Err, zombieRunErr)
	}
	if v.CaptureID != "cap-old" || v.Packets != 9 || v.Alerts != 2 {
		t.Errorf("回填字段丢失: %+v", v)
	}

	// 回填记录必须是"死"的：没有 goroutine / hotpath / 数据源。
	m.mu.Lock()
	restored := m.runs["run-zombie"]
	if restored == nil {
		m.mu.Unlock()
		t.Fatal("回填后 runs 表中找不到 run-zombie")
	}
	hp, cancel, done, src := restored.hp, restored.cancel, restored.done, restored.src
	m.mu.Unlock()
	if hp != nil || cancel != nil || done != nil || src != nil {
		t.Errorf("回填记录不应持有运行期状态: hp=%v cancel=%v done=%v src=%v", hp, cancel, done, src)
	}

	// 已结束记录保持原状态与计数。
	doneView, ok := m.getRun("run-done")
	if !ok {
		t.Fatal("回填后内存中找不到 run-done")
	}
	if doneView.State != runStateDone || doneView.Packets != 4 || doneView.Alerts != 1 {
		t.Errorf("已结束记录回填不一致: %+v", doneView)
	}

	// 僵尸修正应写回存储，避免每次重启重复误判。
	saved := host.Saved()
	foundHealed := false
	for _, rec := range saved {
		if rec.ID == "run-zombie" {
			foundHealed = true
			if rec.State != runStateError || rec.Err != zombieRunErr {
				t.Errorf("僵尸修正未写回存储: %+v", rec)
			}
		}
	}
	if !foundHealed {
		t.Errorf("僵尸修正未调用 RunSave: %+v", saved)
	}
}

// TestModuleWorksWithoutRunStore 验证假 Host 不实现 RunStore 时模块照常工作。
//
// ★ 这是可选扩展的核心约束：类型断言失败时静默跳过，不 panic、不影响 Run。
func TestModuleWorksWithoutRunStore(t *testing.T) {
	cfg := staticTestConfig(t)
	host := newHost(cfg)
	if _, ok := any(host).(plugin.RunStore); ok {
		t.Fatal("测试前提不成立：plugintest.Host 不应实现 plugin.RunStore")
	}

	m := &captureModule{}
	if err := m.start(host, cfg); err != nil {
		t.Fatalf("start 失败: %v", err)
	}
	t.Cleanup(func() { _ = m.stop() })

	run, err := m.addRun(modeStatic, "test:slice", "cap-none", &sliceSource{})
	if err != nil {
		t.Fatalf("addRun 失败: %v", err)
	}
	v := waitRunFinished(t, m, run.ID)
	if v.State != runStateDone {
		t.Errorf("无 RunStore 时 Run 状态 = %q，期望 done", v.State)
	}
}
