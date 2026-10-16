package pluginhost

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/config"
	"flow-monitoring/internal/kernel/eventbus"
	"flow-monitoring/internal/kernel/logging"
	"flow-monitoring/internal/kernel/registry"
)

// TestRealPluginProcessLifecycle 是**真实插件进程**的生命周期验证。
//
// ★ 为什么需要它（踩坑 29）：单测只能覆盖 stopWithTimeout 的算法（超时/幂等/报错），
// 覆盖不到"真起进程 / 真握手 / 真停 / 超时真强杀"。
//
// 通过环境变量 FLOW_TEST_PLUGIN=1 开启（否则跳过，保证无此环境依赖的 CI 依然绿）：
//
//	$env:FLOW_TEST_PLUGIN="1"; go test -count=1 -v -run TestRealPluginProcessLifecycle ./internal/kernel/pluginhost/
//
// 流程：编译 cmd/plugins/importer 到临时目录 → Manager.Start（宿主桥接）→ Launch（握手）→
// StartOne → StopOne（优雅停）→ StartOne（重启）→ ★ StopOne(timeout=1ns)（超时强杀）→ StopAll。
func TestRealPluginProcessLifecycle(t *testing.T) {
	if os.Getenv("FLOW_TEST_PLUGIN") == "" {
		t.Skip("FLOW_TEST_PLUGIN 未设置，跳过真实插件进程测试")
	}

	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("定位仓库根: %v", err)
	}
	pluginDir := t.TempDir()
	binName := "importer"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(pluginDir, binName)

	// 编译真实插件二进制（★ 这一步本身就验证了"插件能被独立编译"）。
	build := exec.Command("go", "build", "-o", binPath, "flow-monitoring/cmd/plugins/importer")
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("编译插件失败: %v\n%s", err, out)
	}
	if _, err := os.Stat(binPath); err != nil {
		t.Fatalf("插件二进制不存在: %v", err)
	}

	cfg := config.Default()
	cfg.PluginDir = pluginDir
	logger := logging.New(logging.LevelWarn, "text", io.Discard)
	bridge := NewBridge(cfg, logger, eventbus.New(), nil)
	mgr := NewManager(pluginDir, cfg, logger, bridge)

	if err := mgr.Start(); err != nil {
		t.Fatalf("Manager.Start（宿主桥接）: %v", err)
	}
	defer func() { _ = mgr.StopAll(context.Background()) }()

	desc := registry.Descriptor{ID: "modules.importer", Name: "importer", Binary: "importer"}
	ctx := context.Background()

	// 1) Launch：真起进程 + 握手 + Dispense。
	if err := mgr.Launch(desc); err != nil {
		t.Fatalf("Launch 真实插件进程: %v", err)
	}
	if st := mgr.State(desc.ID); st != stateLaunched {
		t.Fatalf("Launch 后 state = %q, want %q", st, stateLaunched)
	}
	t.Logf("✓ Launch 成功，state=%s", mgr.State(desc.ID))

	// 2) StartOne：调用模块自己的 Start（依赖 DB 等外部条件，失败不视为本测试失败，只记录）。
	if err := mgr.StartOne(ctx, desc); err != nil {
		t.Logf("⚠ 模块 Start 返回错误（可接受：真实模块可能依赖 DB/配置）: %v", err)
	} else if st := mgr.State(desc.ID); st != stateStarted {
		t.Fatalf("StartOne 成功但 state = %q, want %q", st, stateStarted)
	} else {
		t.Logf("✓ StartOne 成功，state=%s", st)
	}

	// 3) StopOne（宽松超时）：优雅停止必须成功（若模块压根没 Start，Stop 也应能收尾）。
	if err := mgr.StopOne(ctx, desc, 10*time.Second); err != nil {
		t.Fatalf("StopOne（优雅）: %v", err)
	}
	if st := mgr.State(desc.ID); st != stateStopped {
		t.Fatalf("StopOne 后 state = %q, want %q", st, stateStopped)
	}
	t.Logf("✓ StopOne 优雅停止成功，state=%s", mgr.State(desc.ID))

	// 4) ★ StopOne 幂等：已 stopped 再停一次必须成功。
	if err := mgr.StopOne(ctx, desc, time.Second); err != nil {
		t.Fatalf("已停止后再 StopOne 应幂等成功: %v", err)
	}
	t.Logf("✓ StopOne 幂等（已 stopped）")

	// 5) StartOne 重启：stopped 状态下直接 Module.Start（不重新 Launch）。
	if err := mgr.StartOne(ctx, desc); err != nil {
		t.Logf("⚠ 重启时模块 Start 返回错误（可接受）: %v", err)
	}
	t.Logf("重启后 state=%s", mgr.State(desc.ID))

	// 6) ★★ 超时强杀：给 1ns 超时 ⇒ 必须返回 ErrStopTimeout，且进程被强杀、state=stopped。
	errTimeout := mgr.StopOne(ctx, desc, time.Nanosecond)
	if !errors.Is(errTimeout, ErrStopTimeout) {
		t.Fatalf("1ns 超时应得到 ErrStopTimeout，实际 err=%v（state=%s）", errTimeout, mgr.State(desc.ID))
	}
	if st := mgr.State(desc.ID); st != stateStopped {
		t.Fatalf("超时强杀后 state = %q, want %q", st, stateStopped)
	}
	t.Logf("✓ 超时强杀：ErrStopTimeout + state=%s（真实进程已被 Kill）", mgr.State(desc.ID))

	// 7) 超时强杀后还能再次启动（说明进程确实被回收、没有被卡住的半死状态）。
	if err := mgr.StartOne(ctx, desc); err != nil {
		t.Logf("⚠ 强杀后重启时模块 Start 返回错误（可接受）: %v", err)
	}
	t.Logf("强杀后重启 state=%s", mgr.State(desc.ID))
}
