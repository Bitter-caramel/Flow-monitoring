/**
 * 面板：包列表（packet-list）。
 *
 * 通过 registerPanel 自注册；独立面板，不依赖其他面板，
 * 只依赖后端 query-api 与共享 api 客户端。
 */
import { registerPanel } from '../../shell/registry'
import { PacketListPanel } from './Panel'

registerPanel(
  {
    id: 'panels.packet-list',
    name: '包列表',
    version: '1.0.0',
    description: '按 capture 分页查看数据包（Wireshark 风格）',
    layer: 'L1',
    // ★ 只放 static：它查的是 modules.query（已导入的文件）。
    //   动态工作台需要的是"实时包流"，那个能力还没做（阶段 3 之后）；
    //   在那之前放进 live 会让用户误以为能看到实时包。
    workbenches: ['static'],
    group: '数据',
    icon: '▤',
    moduleId: 'modules.query',
  },
  PacketListPanel,
)
