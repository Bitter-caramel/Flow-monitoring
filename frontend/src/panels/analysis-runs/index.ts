/**
 * 面板：分析任务（analysis-runs）。
 *
 * 通过 registerPanel 自注册；静态工作台的入口：
 *   1. 上方列出已导入的抓包文件，点「分析」发起静态 Run；
 *   2. 下方列出 Run 进度，运行中每 2 秒轮询，可点「停止」结束任务。
 *
 * 数据来源：宿主网关反代 /api/v1/captures（query-api）与 /api/capture/runs（capture）。
 */
import { registerPanel } from '../../shell/registry'
import { AnalysisRunsPanel } from './Panel'

registerPanel(
  {
    id: 'panels.analysis-runs',
    name: '分析任务',
    version: '1.0.0',
    description: '选择已导入的抓包文件发起静态分析，并查看任务进度',
    layer: 'L1',
    workbenches: ['static'],
    group: '分析',
    icon: '▶',
    // 捕获能力缺席时入口置灰（发起 Run 依赖 modules.capture）。
    moduleId: 'modules.capture',
  },
  AnalysisRunsPanel,
)
