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
    name: '实时告警',
    version: '1.0.0',
    description: '订阅宿主告警 WebSocket，实时滚动显示（历史 + 增量）',
    layer: 'L1',
    // ★ 只放 live：静态检测要到阶段 3（16-3）才接入，在那之前放进来就是"永远为空的面板"。
    //   过滤逻辑（mode=static/live）已就绪，16-3 完成后把 'static' 加回来即可。
    workbenches: ['live'],
    group: '结果',
    icon: '⚠',
  },
  AlertListPanel,
)
