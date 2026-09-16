package pluginhost

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"

	hplugin "github.com/hashicorp/go-plugin"
	"github.com/hashicorp/go-hclog"

	"flow-monitoring/internal/kernel/config"
	"flow-monitoring/internal/kernel/logging"
	"flow-monitoring/internal/kernel/registry"
	"flow-monitoring/pkg/plugin"
)

// 模块进程状态。
const (
	stateLaunched = "launched" // 进程已起、握手完成，未 Start
	stateStarted  = "started"
	stateStopped  = "stopped"
	stateError    = "error"
)

// Process 一个已启动的模块进程。
type Process struct {
	Desc   registry.Descriptor
	Module plugin.Module // 远程调用代理
	rpc    hplugin.ClientProtocol
	client *hplugin.Client
}

// Manager 模块进程管理器。
//
// 职责：启动宿主桥接服务（模块回连）→ Launch 各模块进程 → StartAll 按拓扑序启动
// → StopAll 逆序关闭。模块的依赖/顺序来自 registry（manifest 文件），不硬编码。
type Manager struct {
	pluginDir string
	cfg       *config.Config
	logger    *logging.Logger
	bridge    *Bridge

	bridgeLn net.Listener

	mu        sync.Mutex
	processes map[string]*Process
	states    map[string]string
	order     []string // 拓扑序（Start 时填充）
}

// NewManager 创建模块进程管理器。
func NewManager(pluginDir string, cfg *config.Config, logger *logging.Logger, bridge *Bridge) *Manager {
	return &Manager{
		pluginDir: pluginDir,
		cfg:       cfg,
		logger:    logger,
		bridge:    bridge,
		processes: make(map[string]*Process),
		states:    make(map[string]string),
	}
}

// Start 启动宿主桥接服务（模块进程据此回连）。
func (m *Manager) Start() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("pluginhost: listen bridge: %w", err)
	}
	m.bridgeLn = ln
	go func() { _ = plugin.ServeHost(ln, m.bridge) }()
	m.logger.Info("plugin host bridge listening", "addr", ln.Addr().String())
	return nil
}

// BridgeAddr 返回宿主桥接地址（写入模块进程环境变量）。
func (m *Manager) BridgeAddr() string {
	if m.bridgeLn == nil {
		return ""
	}
	return m.bridgeLn.Addr().String()
}

// Launch 启动一个模块进程（握手 + Dispense，不调用 Start）。
//
// 依赖顺序由调用方（bootstrap）按 registry.TopologicalSort 决定；这里只负责
// 把进程拉起来并拿到 Module 代理。
func (m *Manager) Launch(desc registry.Descriptor) error {
	bin := filepath.Join(m.pluginDir, desc.Binary)
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("pluginhost: module %s binary not found at %s: %w", desc.ID, bin, err)
	}

	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "FLOW_HOST_BRIDGE="+m.BridgeAddr())

	client := hplugin.NewClient(&hplugin.ClientConfig{
		HandshakeConfig:  plugin.Handshake,
		Plugins:          map[string]hplugin.Plugin{plugin.ModulePluginName: &plugin.ModulePlugin{}},
		Cmd:              cmd,
		AllowedProtocols: plugin.AllowedProtocols,
		Managed:          true,
		Logger:           hclog.New(&hclog.LoggerOptions{Name: "plugin", Level: hclog.Warn, Output: os.Stderr}),
		SyncStderr:       os.Stderr, // 模块进程的 stderr 回流到宿主 stderr（便于排障）
		SyncStdout:       os.Stdout,
	})

	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return fmt.Errorf("pluginhost: connect %s: %w", desc.ID, err)
	}
	raw, err := rpcClient.Dispense(plugin.ModulePluginName)
	if err != nil {
		client.Kill()
		return fmt.Errorf("pluginhost: dispense %s: %w", desc.ID, err)
	}
	mod, ok := raw.(plugin.Module)
	if !ok {
		client.Kill()
		return fmt.Errorf("pluginhost: %s: unexpected rpc type %T", desc.ID, raw)
	}

	// 一致性校验：模块自报 manifest 与声明文件不符时告警（不阻断，便于调试）
	if mf := mod.Manifest(); mf.ID != "" && mf.ID != desc.ID {
		m.logger.Warn("module manifest id mismatch", "declared", desc.ID, "reported", mf.ID)
	}

	m.mu.Lock()
	m.processes[desc.ID] = &Process{Desc: desc, Module: mod, rpc: rpcClient, client: client}
	m.states[desc.ID] = stateLaunched
	m.mu.Unlock()
	m.logger.Info("module process launched", "id", desc.ID, "binary", desc.Binary)
	return nil
}

// StartAll 按拓扑序启动所有已 Launch 的模块。
func (m *Manager) StartAll(order []registry.Descriptor) error {
	m.mu.Lock()
	m.order = make([]string, 0, len(order))
	for _, d := range order {
		m.order = append(m.order, d.ID)
	}
	m.mu.Unlock()

	for _, desc := range order {
		m.mu.Lock()
		p := m.processes[desc.ID]
		m.mu.Unlock()
		if p == nil {
			continue // 未 Launch 的模块跳过（如未提供二进制）
		}
		if err := p.Module.Start(); err != nil {
			m.setState(desc.ID, stateError)
			return fmt.Errorf("pluginhost: start %s: %w", desc.ID, err)
		}
		m.setState(desc.ID, stateStarted)
		m.logger.Info("module started", "id", desc.ID)
	}
	return nil
}

// StopAll 逆序停止模块进程并回收。
func (m *Manager) StopAll(_ context.Context) error {
	m.mu.Lock()
	order := append([]string(nil), m.order...)
	procs := make(map[string]*Process, len(m.processes))
	for k, v := range m.processes {
		procs[k] = v
	}
	m.mu.Unlock()

	var firstErr error
	for i := len(order) - 1; i >= 0; i-- {
		if p, ok := procs[order[i]]; ok {
			if err := p.Module.Stop(); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("pluginhost: stop %s: %w", order[i], err)
			}
			p.client.Kill()
			// 兜底回滚：进程异常退出时其服务注册/HTTP 路由可能未清理
			m.bridge.UnregisterByModule(order[i])
			m.setState(order[i], stateStopped)
		}
	}
	// 关闭桥接监听
	if m.bridgeLn != nil {
		_ = m.bridgeLn.Close()
	}
	return firstErr
}

// State 查询模块进程状态。
func (m *Manager) State(id string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.states[id]
}

// States 返回所有模块状态快照。
func (m *Manager) States() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]string, len(m.states))
	for k, v := range m.states {
		out[k] = v
	}
	return out
}

// Processes 返回所有模块进程快照（含远程 Module 代理，供健康检查探活）。
func (m *Manager) Processes() map[string]*Process {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]*Process, len(m.processes))
	for k, v := range m.processes {
		out[k] = v
	}
	return out
}

func (m *Manager) setState(id, state string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[id] = state
}
