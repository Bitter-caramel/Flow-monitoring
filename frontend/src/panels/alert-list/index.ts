/**
 * 面板：实时告警（alert-list）。
 *
 * 通过 registerPanel 自注册；数据由宿主自身提供（/api/alerts + /api/ws/alerts），
 * 不依赖任何后端模块 ⇒ moduleId 留空（缺省 = 宿主面板，永远可用）。
 */
import { registerPanel } from '../../shell/registry'
import { AlertListPanel } from './Panel'

registerPanel(
  {
    id: 'panels.alert-list',
    name: '告警',
    version: '1.0.0',
    description: '订阅宿主告警 WebSocket，实时滚动显示（历史 + 增量）',
    layer: 'L1',
    // ★ live + static：16-3 起静态分析已真的能产出告警（mode=static），
    //   放回静态工作台不再是从前那个"永远为空的面板"。
    workbenches: ['live', 'static'],
    group: '结果',
    icon: '⚠',
  },
  AlertListPanel,
)
