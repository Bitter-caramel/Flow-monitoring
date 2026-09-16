// Package health 是平台的"体检"底座（L0 内核）。
//
// 聚合所有模块进程的状态与健康探针，对外输出 /healthz 报告。
// 设计依据 v3 流程梯队 1.8：「health：能报告我还活着、哪个部件坏了」。
package health

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"flow-monitoring/internal/kernel/pluginhost"
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
	State   string `json:"state"`             // 进程状态（launched/started/stopped/error）
	Healthy bool   `json:"healthy"`           // 综合健康（State==started 且探针健康）
	Message string `json:"message,omitempty"` // 探针或错误信息
}

// Report 健康报告（/healthz 返回体）。
type Report struct {
	Status  Status         `json:"status"`
	Time    time.Time      `json:"time"`
	Uptime  time.Duration  `json:"uptime_ms"` // 毫秒
	Modules []ModuleHealth `json:"modules"`
}

// Health 健康聚合器（线程安全；每次 Report 实时聚合，不缓存）。
type Health struct {
	mgr       *pluginhost.Manager
	startedAt time.Time
}

// New 创建 Health（mgr 可为 nil，此时只报告 uptime 与空模块列表）。
func New(mgr *pluginhost.Manager) *Health {
	return &Health{mgr: mgr, startedAt: time.Now()}
}

// Handler 返回 /healthz HTTP handler。
//
// 返回 200（ok/degraded）或 503（down）。
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
	if h.mgr == nil {
		return rep
	}

	states := h.mgr.States()
	procs := h.mgr.Processes()

	// 稳定输出：按 ID 排序
	ids := make([]string, 0, len(procs))
	for id := range procs {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	overall := StatusOK
	for _, id := range ids {
		p := procs[id]
		mh := ModuleHealth{
			ID:      id,
			State:   states[id],
			Healthy: true,
		}

		if states[id] != "started" {
			mh.Healthy = false
			if states[id] == "error" {
				mh.Message = "module in error state"
			} else if states[id] == "stopped" {
				mh.Message = "module stopped"
			} else {
				mh.Message = "module not started"
			}
		}

		// 探活：远程调用模块 Health()（进程已死时返回不健康）
		if hs := p.Module.Health(); !hs.Healthy {
			mh.Healthy = false
			if hs.Message != "" {
				mh.Message = hs.Message
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
