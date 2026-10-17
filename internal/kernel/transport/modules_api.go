package transport

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"flow-monitoring/internal/kernel/modulecontrol"
)

// errBadRequest 标记"请求参数错误"：writeErr 据此返回 400。
var errBadRequest = errors.New("transport: 请求参数错误")

// RegisterModulesAPI 把模块控制面（modulecontrol.Service）挂到宿主 HTTP 上。
//
// 路由用既有 Server.HandleFunc（真实签名：func (s *Server) HandleFunc(methodPattern string,
// fn http.HandlerFunc)；本项目没有 Server.Handle，等价写法是 s.Mux().HandleFunc）注册；
// 路径参数用 Go 1.22+ ServeMux 的 {id}。所有响应都是 JSON。
//
// ★ 行为实现只有 modulecontrol 一份，本文件只是薄壳，不复制任何业务逻辑。
func RegisterModulesAPI(s *Server, svc *modulecontrol.Service) {
	if s == nil || svc == nil {
		return
	}
	a := &modulesAPI{svc: svc}
	s.HandleFunc("GET /api/modules", a.list)
	s.HandleFunc("GET /api/modules/graph", a.graph)
	s.HandleFunc("GET /api/modules/selfcheck", a.selfcheck)
	s.HandleFunc("GET /api/modules/{id}", a.show)
	s.HandleFunc("GET /api/modules/{id}/impact", a.impact)
	s.HandleFunc("POST /api/modules/{id}/enable", a.enable)
	s.HandleFunc("POST /api/modules/{id}/disable", a.disable)
}

// modulesAPI 控制面 HTTP 薄壳（唯一依赖是 modulecontrol.Service）。
type modulesAPI struct {
	svc *modulecontrol.Service
}

// list GET /api/modules → List()。
func (a *modulesAPI) list(w http.ResponseWriter, r *http.Request) {
	views, err := a.svc.List()
	if err != nil {
		writeErr(w, err)
		return
	}
	if views == nil { // 保证空目录也返回 []，不是 null
		views = []modulecontrol.ModuleView{}
	}
	WriteJSON(w, http.StatusOK, views)
}

// graph GET /api/modules/graph → Graph()。
func (a *modulesAPI) graph(w http.ResponseWriter, r *http.Request) {
	g, err := a.svc.Graph()
	if err != nil {
		writeErr(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, g)
}

// selfcheck GET /api/modules/selfcheck → SelfCheck()。
func (a *modulesAPI) selfcheck(w http.ResponseWriter, r *http.Request) {
	rep, err := a.svc.SelfCheck()
	if err != nil {
		writeErr(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, rep)
}

// show GET /api/modules/{id} → Show(id)；不存在 ⇒ 404。
func (a *modulesAPI) show(w http.ResponseWriter, r *http.Request) {
	v, err := a.svc.Show(r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, v)
}

// impact GET /api/modules/{id}/impact → Impact(id)；不存在 ⇒ 404。
func (a *modulesAPI) impact(w http.ResponseWriter, r *http.Request) {
	imp, err := a.svc.Impact(r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, imp)
}

// enable POST /api/modules/{id}/enable → SetEnabledCascade(ctx, id, true)。
//
// ★ 这里将来接 modules.auth 的鉴权与审计
func (a *modulesAPI) enable(w http.ResponseWriter, r *http.Request) {
	res, err := a.svc.SetEnabledCascade(r.Context(), r.PathValue("id"), true)
	if err != nil {
		writeErr(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, res)
}

// disable POST /api/modules/{id}/disable。
//
//   - ?dry_run=1：只返回影响面（Impact，含 can_disable），不改清单、不停模块 ⇒ 200；
//     can_disable=false 也是"预演结果"，仍 200，不是错误。
//   - 不带 dry_run：SetEnabledCascade(ctx, id, false)（级联先停消费者、最后目标）。
//     被拒（core / 连带 core）⇒ 409；级联里有失败（Failed 非空）⇒ 仍 200，
//     且 Failed 如实带回，绝不伪装成全成功。
//
// ★ 这里将来接 modules.auth 的鉴权与审计
func (a *modulesAPI) disable(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dry, err := dryRun(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	if dry {
		imp, err := a.svc.Impact(id)
		// ★ dry_run 也记审计（标 dry_run:true）；审计不影响主流程。
		a.svc.AuditDryRun(r.Context(), id, false, err)
		if err != nil {
			writeErr(w, err)
			return
		}
		WriteJSON(w, http.StatusOK, imp)
		return
	}

	res, err := a.svc.SetEnabledCascade(r.Context(), id, false)
	if err != nil {
		writeErr(w, a.coreBlockErr(id, err))
		return
	}
	WriteJSON(w, http.StatusOK, res)
}

// coreBlockErr 把 modulecontrol 对"连带停 core"的拒绝归一到 ErrCoreModule。
//
// 背景（以现有实现为准）：modulecontrol.SetEnabledCascade 对"目标是 core"返回
// ErrCoreModule；但对"非 core 目标、连带会停 core"返回的是普通 fmt.Errorf（未包哨兵），
// 故这里用**只读**的 Impact(id).CanDisable 判定，映射成 409 —— 不匹配错误文本。
func (a *modulesAPI) coreBlockErr(id string, err error) error {
	if errors.Is(err, modulecontrol.ErrNotFound) || errors.Is(err, modulecontrol.ErrCoreModule) {
		return err
	}
	if imp, ierr := a.svc.Impact(id); ierr == nil && !imp.CanDisable {
		return fmt.Errorf("%w: %v", modulecontrol.ErrCoreModule, err)
	}
	return err
}

// dryRun 解析 ?dry_run=（缺省 false）。值不是合法 bool ⇒ 参数错（400）。
func dryRun(r *http.Request) (bool, error) {
	v := r.URL.Query().Get("dry_run")
	if v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%w: dry_run=%q 不是合法 bool", errBadRequest, v)
	}
	return b, nil
}

// writeErr 统一错误映射：
//
//	ErrNotFound        ⇒ 404
//	ErrCoreModule      ⇒ 409
//	ErrInProcessModule ⇒ 409（内嵌模块没有独立进程可启停，属语义拒绝，不是服务器错误）
//	参数错              ⇒ 400
//	其它                ⇒ 500
//
// ★ 一律用 errors.Is 判定，绝不匹配错误文本；响应体统一为 {"error": ...}。
func writeErr(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, modulecontrol.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, modulecontrol.ErrCoreModule):
		status = http.StatusConflict
	case errors.Is(err, modulecontrol.ErrInProcessModule):
		status = http.StatusConflict
	case errors.Is(err, errBadRequest):
		status = http.StatusBadRequest
	}
	WriteJSON(w, status, map[string]string{"error": err.Error()})
}
