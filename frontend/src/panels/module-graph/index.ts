/**
 * 面板：模块拓扑（module-graph）。
 *
 * 通过 registerPanel 自注册；只依赖后端 /api/modules/graph 与共享 api 客户端。
 */
import { registerPanel } from '../../shell/registry'
import { ModuleGraphPanel } from './Panel'

registerPanel(
  {
    id: 'panels.module-graph',
    name: '模块拓扑',
    version: '0.1.0',
    description: '模块依赖分层拓扑图（自研 SVG）',
    layer: 'L2',
    workbenches: ['console'],
    group: '模块',
    icon: '◈',
  },
  ModuleGraphPanel,
)
