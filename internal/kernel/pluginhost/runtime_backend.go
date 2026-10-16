package pluginhost

import (
	"context"
	"fmt"
	"time"

	"flow-monitoring/internal/kernel/registry"
)

// DefaultStopTimeout 是单模块停止的默认超时（NewRuntimeBackend 的 timeout<=0 时生效）。
const DefaultStopTimeout = 10 * time.Second

// RuntimeBackend 把 Manager + Registry 适配成"运行期启停后端"。
//
// ★ 方法集与 modulecontrol.RuntimeBackend 一致，但**本文件不 import modulecontrol** ——
// Go 是结构化接口，装配层直接把它赋给 modulecontrol.RuntimeBackend 即可编译通过。
// 这样 pluginhost（内核·插件宿主）不依赖 modulecontrol（控制面），依赖方向不反过来。
type RuntimeBackend struct {
	mgr     *Manager
	reg     *registry.Registry
	timeout time.Duration
}

// NewRuntimeBackend 创建适配器。timeout <= 0 时用 DefaultStopTimeout。
func NewRuntimeBackend(mgr *Manager, reg *registry.Registry, timeout time.Duration) *RuntimeBackend {
	if timeout <= 0 {
		timeout = DefaultStopTimeout
	}
	return &RuntimeBackend{mgr: mgr, reg: reg, timeout: timeout}
}

// States 返回运行态快照（模块 id -> launched/started/stopped/error）。
// mgr 为 nil 时返回空 map（调用方按"未知"处理），不是 nil。
func (b *RuntimeBackend) States() map[string]string {
	if b == nil || b.mgr == nil {
		return map[string]string{}
	}
	st := b.mgr.States()
	if st == nil {
		return map[string]string{}
	}
	return st
}

// StopOne 停止单个模块（按 id 从注册表找到 Descriptor，再交给 Manager 优雅停止 + 超时兜底）。
func (b *RuntimeBackend) StopOne(ctx context.Context, id string) error {
	desc, err := b.descriptor(id)
	if err != nil {
		return err
	}
	return b.mgr.StopOne(ctx, desc, b.timeout)
}

// StartOne 启动单个模块（幂等；未 Launch 过会先 Launch）。
func (b *RuntimeBackend) StartOne(ctx context.Context, id string) error {
	desc, err := b.descriptor(id)
	if err != nil {
		return err
	}
	return b.mgr.StartOne(ctx, desc)
}

func (b *RuntimeBackend) descriptor(id string) (registry.Descriptor, error) {
	if b == nil || b.mgr == nil {
		return registry.Descriptor{}, fmt.Errorf("pluginhost: 运行期后端未接入 Manager（无法操作 %s）", id)
	}
	if b.reg == nil {
		return registry.Descriptor{}, fmt.Errorf("pluginhost: 运行期后端未接入 Registry（无法解析 %s）", id)
	}
	desc, ok := b.reg.Get(id)
	if !ok {
		return registry.Descriptor{}, fmt.Errorf("pluginhost: 模块 %s 不在注册表里", id)
	}
	return desc, nil
}
