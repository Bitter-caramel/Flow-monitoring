package importer

import (
	"net/http"

	"flow-monitoring/internal/modules/common/hoststore"
	"flow-monitoring/internal/modules/packetstore"
	"flow-monitoring/pkg/plugin"
)

// Module 返回流量导入模块的定义（进程入口 cmd/plugins/importer 使用）。
//
// 与 query 的样板同构，唯一差异：导入除"索引存储"外还需要"原始文件仓库"，
// 而仓库目录来自宿主配置（ConfigSnapshot.DataDir）。两者都在 MakeHandler 阶段
// 通过宿主桥构造，业务代码（Importer/ImportHandler）本身零改动。
//
// 对应 registry/backend-modules/importer.json 里的声明（二者应保持一致）。
func Module() *plugin.Runtime {
	return &plugin.Runtime{
		Spec: plugin.Manifest{
			ID:       "modules.importer",
			Name:     "流量导入",
			Version:  "1.0.0",
			Layer:    plugin.LayerFeature,
			HTTPBase: "/api/v1/captures/import",
			Provides: []string{"importer.api"},
		},
		MakeHandler: func(host plugin.Host) (http.Handler, error) {
			// 原始文件落宿主配置的 DataDir；索引读写走宿主存储桥（模块不直连数据库）
			st, err := packetstore.New(host.Config().DataDir, hoststore.New(host))
			if err != nil {
				return nil, err
			}
			return New(st).ImportHandler(), nil
		},
	}
}
