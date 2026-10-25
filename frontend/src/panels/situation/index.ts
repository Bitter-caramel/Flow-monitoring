/**
 * 面板：态势（situation）。
 *
 * 数据由 situation 模块提供（GET /api/situation，经宿主网关反代）。
 * 它是**持续聚合**的视图，所以用轮询而不是 WebSocket。
 */
import { registerPanel } from '../../shell/registry'
import { SituationPanel } from './Panel'

registerPanel(
  {
    id: 'panels.situation',
    name: '态势',
    version: '1.0.0',
    description: '按源 IP 聚合的攻击态势（评分 / 命中次数 / 等级）',
    layer: 'L1',
    workbenches: ['live'],
    group: '结果',
    icon: '◎',
  },
  SituationPanel,
)
