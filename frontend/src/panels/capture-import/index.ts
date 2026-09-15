/**
 * 面板：抓包导入（capture-import）。
 *
 * 通过 registerPanel 自注册到面板注册表；shell 读取后挂载本组件。
 * 该面板只负责"上传文件 + 展示 capture 列表"，数据来源是后端 API。
 */
import { registerPanel } from '../../shell/registry'
import { CaptureImportPanel } from './Panel'

registerPanel(
  {
    id: 'panels.capture-import',
    name: '抓包导入',
    version: '1.0.0',
    description: '上传 pcap/pcapng 文件并查看 capture 列表',
    layer: 'L1',
    icon: '⇪',
  },
  CaptureImportPanel,
)
