/**
 * Shell 外壳 —— 设计文档 §4 的四区骨架。
 *
 *   ┌───────────────────────────────────────────────┐
 *   │ 顶栏 TopBar                                     │  ← 产品名 / 搜索 / 主题 / 密度 / 连接
 *   ├──────────┬────────────────────────────────────┤
 *   │ 左导航    │ 工作区（面板挂载点，独立滚动）        │
 *   │ LayerNav  │                                     │
 *   │ (按层分组) │                                     │
 *   ├──────────┴────────────────────────────────────┤
 *   │ 状态栏 StatusBar                                │  ← 模块数/启用数 · 自检 · 刷新
 *   └───────────────────────────────────────────────┘
 *
 * 只做三件事：
 *   1. 读注册表，交给 LayerNav 渲染分层导航；
 *   2. 在工作区挂载选中的面板组件（shell 不感知其实现）；
 *   3. 持有一个 useAppStatus，把连接状态分发给 TopBar / StatusBar（单一数据源）。
 *
 * 整体高度撑满（h-screen + flex-col），仅工作区 overflow-auto ⇒ 顶栏/导航/状态栏固定。
 */
import { panelRegistry } from './registry'
import type { PanelPlugin } from './registry'
import { LayerNav } from './LayerNav'
import { TopBar } from './TopBar'
import { StatusBar } from './StatusBar'
import { useAppStatus } from './useAppStatus'
import { useActivePanel } from './useActivePanel'

export function App() {
  // ★ 当前面板来自 URL（hash 路由，URL 是唯一数据源）：刷新保持、可分享、可前进后退。
  const { activeId, select } = useActivePanel()

  // 全局状态只请求一次，顶栏与状态栏共用（避免重复打后端）。
  const status = useAppStatus()

  const active: PanelPlugin | undefined = panelRegistry.query(activeId)
  const ActiveComponent = active?.component

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-app text-fg">
      <TopBar connection={status.state} />

      <div className="flex min-h-0 flex-1">
        <LayerNav activeId={activeId} onSelect={select} />

        <main className="min-w-0 flex-1 overflow-auto p-4">
          {ActiveComponent ? (
            <ActiveComponent />
          ) : (
            <div className="flex h-full items-center justify-center text-dim">请注册至少一个面板</div>
          )}
        </main>
      </div>

      <StatusBar status={status} />
    </div>
  )
}
