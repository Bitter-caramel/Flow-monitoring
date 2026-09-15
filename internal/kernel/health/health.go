package health

import (
	"encoding/json"
	"net/http"
	"time"

	"flow-monitoring/internal/kernel/lifecycle"
	"flow-monitoring/internal/kernel/registry"
)

// Status 整体健康状态等级。
type Status string

const (
	StatusOK       Status = "ok"       // 全部健康
	StatusDegraded Status = "degraded" // 部分模块异常，但核心仍在运行
	StatusDown     Status = "down"     // 核心模块不可用
)

// ModuleHealth 单个模块的健康明细。
type ModuleHealth struct {
	ID      string `json:"id"`
	State   string `json:"state"`             // 生命周期状态（Started/Error/...）
	Healthy bool   `json:"healthy"`           // 综合健康（State==Started 且探针健康）
	Message string `json:"message,omitempty"` // 探针或错误信息
}

// Report 健康报告（/healthz 返回体）。
type Report struct {
	Status  Status         `json:"status"`
	Time    time.Time      `json:"time"`
	Uptime  time.Duration  `json:"uptime_ms"` // 毫秒
	Modules []ModuleHealth `json:"modules"`
}

// Health 健康聚合器。
//
// 线程安全；创建后绑定一个 registry 和 lifecycle.Coordinator。
// Handler() 每次调用都实时聚合状态（不缓存，保证最新）。
type Health struct {
	reg      *registry.Registry
	lc       *lifecycle.Coordinator
	startedAt time.Time
}

// New 创建 Health。
//
// 参数：
//   - reg: 模块注册表（读 HealthFn 探针）
//   - lc: 生命周期协调器（读模块状态）
//
// reg/lc 可为 nil（测试隔离场景）：此时只报告自身 uptime 与空模块列表。
func New(reg *registry.Registry, lc *lifecycle.Coordinator) *Health {
	return &Health{reg: reg, lc: lc, startedAt: time.Now()}
}

// Handler 返回 /healthz HTTP handler。
//
// 返回 200（ok/degraded）或 503（down）。
// 判断规则：
//   - 有模块 State==Error → degraded（若核心模块则 down，暂统一按 degraded）
//   - 有模块探针 Healthy==false → degraded
//   - 全部 Started 且探针健康 → ok
//   - 无任何模块信息 → ok（空平台刚启动）
func (h *Health) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rep := h.Report()
		code := http.StatusOK
		if rep.Status == StatusDown {
			code = http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(rep)
	})
}

// Report 生成当前健康报告快照。
func (h *Health) Report() Report {
	rep := Report{
		Status:  StatusOK,
		Time:    time.Now(),
		Uptime:  time.Since(h.startedAt),
		Modules: []ModuleHealth{},
	}

	var states map[registry.ModuleID]lifecycle.State
	if h.lc != nil {
		states = h.lc.States()
	}

	// 若无模块注册，直接返回 ok（空平台）
	if h.reg == nil {
		return rep
	}

	overall := StatusOK
	for _, m := range h.reg.List() {
		mh := ModuleHealth{
			ID:      string(m.ID),
			State:   lifecycle.StateCreated.String(), // 默认未启动
			Healthy: true,
		}

		// 1. 生命周期状态
		if states != nil {
			if st, ok := states[m.ID]; ok {
				mh.State = st.String()
				if st == lifecycle.StateError {
					mh.Healthy = false
					mh.Message = "module in error state"
				}
			} else {
				mh.Healthy = false
				mh.Message = "module not started"
			}
		}

		// 2. 自定义探针
		if m.HealthFn != nil {
			hs := m.HealthFn()
			if !hs.Healthy {
				mh.Healthy = false
				if hs.Message != "" {
					mh.Message = hs.Message
				}
			}
		}

		if !mh.Healthy {
			overall = StatusDegraded
		}
		rep.Modules = append(rep.Modules, mh)
	}

	rep.Status = overall
	return rep
}
