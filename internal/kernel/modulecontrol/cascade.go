package modulecontrol

import (
	"context"
	"fmt"
	"time"

	"flow-monitoring/internal/kernel/registry"
)

// 运行态字符串：与 pluginhost.Manager 的未导出状态常量一一对应。
// ★ 本包不 import pluginhost（避免控制面绑死在插件实现上），因此这里用字符串表达。
//
//	pluginhost.stateLaunched = "launched"
//	pluginhost.stateStarted  = "started"
//	pluginhost.stateStopped  = "stopped"
//	pluginhost.stateError    = "error"
const (
	StateLaunched = "launched" // 进程已起、握手完成，未 Start
	StateStarted  = "started"  // 已启动（正常服务中）
	StateStopped  = "stopped"  // 已停止
	StateError    = "error"    // 出错
)

// DefaultStopTimeout 是单模块停止的默认超时（Options.StopTimeout 为 0 时生效）。
const DefaultStopTimeout = 10 * time.Second

// RuntimeBackend 是**可选的**运行期启停后端：给了就能真的停/启，
// 没给（nil）就保持 12-2 的行为（只改清单 + 提示重启生效）。
// ★ 12-3b 会用 pluginhost.Manager 实现它；本步只用假实现测试。
type RuntimeBackend interface {
	// States 返回当前运行态（模块 id -> StateLaunched/Started/Stopped/Error）；未知模块可不出现。
	States() map[string]string
	// StartOne 启动单个模块（幂等：已在运行应直接成功）。
	StartOne(ctx context.Context, id string) error
	// StopOne 停止单个模块（§5.2 的语义：优雅停止 + 超时兜底由实现负责）。
	StopOne(ctx context.Context, id string) error
}

// StepResult 级联里**单个模块**的一步结果（如实记账，不吞错）。
type StepResult struct {
	ID     string `json:"id"`
	Action string `json:"action"` // "stop" 或 "start"
	OK     bool   `json:"ok"`
	Err    string `json:"err,omitempty"`
}

// CascadeResult 一次级联启停的完整账本。
type CascadeResult struct {
	ID          string       `json:"id"`
	Enabled     bool         `json:"enabled"`
	Steps       []StepResult `json:"steps"`   // 实际执行顺序（与 Impact.Dependents 同序）
	Stopped     []string     `json:"stopped"` // 成功的模块（顺序同上）
	Failed      []string     `json:"failed"`  // 失败的模块
	RestartHint string       `json:"restart_hint,omitempty"`
	Applied     bool         `json:"applied"` // false = 没有后端，只改了清单
}

// WithRuntime 注入运行期后端（装配期或测试用；nil 允许 = 退回只改清单的 12-2 行为）。
func (s *Service) WithRuntime(rt RuntimeBackend) *Service {
	s.runtime = rt
	return s
}

// runtimeStates 取当前运行态；无后端时返回 nil。
func (s *Service) runtimeStates() map[string]string {
	if s.runtime == nil {
		return nil
	}
	return s.runtime.States()
}

// stateOf 从运行态表里取模块状态；未出现或空串 ⇒ StateUnknown。
func stateOf(states map[string]string, id string) string {
	if st, ok := states[id]; ok && st != "" {
		return st
	}
	return StateUnknown
}

// SetEnabledCascade 是带级联的启停（Disable 时先停依赖它的模块）。
//
// ★ 无后端时：退化为 SetEnabled（只改清单 + RestartHint），Applied=false。
//
// 关闭时用 Impact(id).Dependents（已是"先关最末端消费者"的反向拓扑序）逐个 StopOne，
// 最后才停目标本身；启用时只启它自己，不级联启动依赖者。
func (s *Service) SetEnabledCascade(ctx context.Context, id string, enabled bool) (CascadeResult, error) {
	// 先按磁盘最新状态校验（存在性 + core 保护），失败时绝不动清单/后端。
	reg, err := registry.Load(s.dir)
	if err != nil {
		return CascadeResult{}, fmt.Errorf("modulecontrol: 重新加载清单目录 %s: %w", s.dir, err)
	}
	s.reg = reg
	d, ok := s.reg.Get(id)
	if !ok {
		return CascadeResult{}, ErrNotFound
	}
	if !enabled && d.Core {
		return CascadeResult{}, ErrCoreModule
	}

	if enabled {
		return s.cascadeStart(ctx, id)
	}
	return s.cascadeStop(ctx, id)
}

// cascadeStop 执行停用：级联先停消费者、最后停目标；然后写清单。
func (s *Service) cascadeStop(ctx context.Context, id string) (CascadeResult, error) {
	imp, err := s.Impact(id)
	if err != nil {
		return CascadeResult{}, err
	}
	// ★ CanDisable=false（目标是 core，或连带会停 core）⇒ 一律拒绝且不动任何东西。
	if !imp.CanDisable {
		return CascadeResult{}, fmt.Errorf("modulecontrol: 不能停用 %s: %s", id, imp.BlockReason)
	}

	res := CascadeResult{
		ID:      id,
		Enabled: false,
		Steps:   []StepResult{},
		Stopped: []string{},
		Failed:  []string{},
	}

	// ★ 无后端：退化为 12-2 的 SetEnabled（只改清单 + RestartHint），不做任何运行期动作。
	if s.runtime == nil {
		if _, err := s.SetEnabled(id, false); err != nil {
			return CascadeResult{}, err
		}
		res.RestartHint = RestartHint
		res.Applied = false
		return res, nil
	}

	// 关闭顺序 = Dependents（先关最末端消费者）+ 目标本身（最后）。
	order := make([]string, 0, len(imp.Dependents)+1)
	order = append(order, imp.Dependents...)
	order = append(order, id)

	for _, m := range order {
		stepErr := s.stopOne(ctx, m)
		sr := StepResult{ID: m, Action: "stop", OK: stepErr == nil}
		if stepErr != nil {
			sr.Err = stepErr.Error()
			res.Failed = append(res.Failed, m)
		} else {
			res.Stopped = append(res.Stopped, m)
		}
		res.Steps = append(res.Steps, sr)
		// ★ 某步失败**不中止**：继续停其余模块，把失败如实记进 Failed。
		// 理由：用户意图是禁用该模块，能停尽停（少留一个运行中的消费者）比半途而废更安全；
		// 且无论成败都如实写进 Steps，调用方据此展示"哪些停了、哪些没停"。
	}

	// 最后写清单（用户意图是禁用；即便级联中有失败也写，Failed 已如实记录）。
	if _, err := s.SetEnabled(id, false); err != nil {
		return res, err
	}
	res.Applied = true
	return res, nil
}

// cascadeStart 执行启用：★ 只启它自己（不级联启动依赖者），然后写清单。
//
// 理由：启动依赖者应由调用方显式决定，避免"启一个带出一串"造成难以预期的副作用
// （依赖者可能还有很多下游，级联启动面太大）。
func (s *Service) cascadeStart(ctx context.Context, id string) (CascadeResult, error) {
	res := CascadeResult{
		ID:      id,
		Enabled: true,
		Steps:   []StepResult{},
		Stopped: []string{},
		Failed:  []string{},
	}

	// ★ 无后端：退化为 12-2 的 SetEnabled（只改清单 + RestartHint）。
	if s.runtime == nil {
		if _, err := s.SetEnabled(id, true); err != nil {
			return CascadeResult{}, err
		}
		res.RestartHint = RestartHint
		res.Applied = false
		return res, nil
	}

	stepErr := s.runtime.StartOne(ctx, id)
	sr := StepResult{ID: id, Action: "start", OK: stepErr == nil}
	if stepErr != nil {
		sr.Err = stepErr.Error()
		res.Failed = append(res.Failed, id)
	} else {
		res.Stopped = append(res.Stopped, id) // "成功的模块"（Stopped 记录成功执行的模块）
	}
	res.Steps = append(res.Steps, sr)

	// 写清单，保证重启后仍启用（与停用对称）。
	if _, err := s.SetEnabled(id, true); err != nil {
		return res, err
	}
	res.Applied = true
	return res, nil
}

// stopOne 调后端停单个模块，并套上 StopTimeout（超时兜底由后端/12-3b 负责落实）。
func (s *Service) stopOne(ctx context.Context, id string) error {
	if s.stopTimeout <= 0 {
		return s.runtime.StopOne(ctx, id)
	}
	cctx, cancel := context.WithTimeout(ctx, s.stopTimeout)
	defer cancel()
	return s.runtime.StopOne(cctx, id)
}
