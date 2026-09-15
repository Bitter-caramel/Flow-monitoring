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
    icon: '▤',
  },
  PacketListPanel,
)
