package query

import (
	"net/http"

	"flow-monitoring/internal/modules/common/hoststore"
	"flow-monitoring/pkg/plugin"
)

// Module 返回查询服务的模块定义（进程入口 cmd/plugins/query 使用）。
//
// 这是"业务代码如何注册成插件"的最小样板：
//   - Spec 声明身份/层/HTTP 路由前缀/提供的服务名；
//   - MakeHandler 在宿主桥就绪后构造 HTTP handler；
//   - 业务逻辑（Service/Handler）完全复用既有代码，通过 hoststore 适配器
//     把宿主桥包装成 storage.Storage，零改动接入。
//
// 对应 registry/backend-modules/query.json 里的声明（二者应保持一致）。
func Module() *plugin.Runtime {
	return &plugin.Runtime{
		Spec: plugin.Manifest{
			ID:       "modules.query",
			Name:     "查询服务",
			Version:  "1.0.0",
			Layer:    plugin.LayerFeature,
			HTTPBase: "/api/v1/captures",
			Provides: []string{"query.api"},
		},
		MakeHandler: func(host plugin.Host) (http.Handler, error) {
			svc := New(hoststore.New(host))
			return svc.Handler(), nil
		},
	}
}
