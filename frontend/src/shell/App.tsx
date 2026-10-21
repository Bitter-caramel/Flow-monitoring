/**
 * Shell 外壳 —— 设计文档 §4 的四区骨架。
 *
 *   ┌───────────────────────────────────────────────┐
 *   │ 顶栏 TopBar                                     │  ← 产品名 / 工作台 tab / 搜索 / 主题 / 密度 / 连接
 *   ├──────────┬────────────────────────────────────┤
 *   │ 左导航    │ 工作区（面板挂载点，独立滚动）        │
 *   │ SideNav   │                                     │
 *   │ (按工作台) │                                     │
 *   ├──────────┴────────────────────────────────────┤
 *   │ 状态栏 StatusBar                                │  ← 模块数/启用数 · 自检 · 刷新
 *   └───────────────────────────────────────────────┘
 *
 * 只做三件事：
 *   1. 读注册表，交给 SideNav 渲染当前工作台的面板导航；
 *   2. 在工作区挂载选中的面板组件（shell 不感知其实现）；
 *   3. 持有一个 useAppStatus，把连接状态分发给 TopBar / StatusBar（单一数据源）。
 *
 * 整体高度撑满（h-screen + flex-col），仅工作区 overflow-auto ⇒ 顶栏/导航/状态栏固定。
 */
import { useEffect, useState } from 'react'
import { isAvailable, panelRegistry, setEnabledModules } from './registry'
import type { PanelPlugin } from './registry'
import { SideNav } from './SideNav'
import { TopBar } from './TopBar'
import { StatusBar } from './StatusBar'
import { useAppStatus } from './useAppStatus'
import { useActivePanel } from './useActivePanel'
import { PanelErrorBoundary } from './ErrorBoundary'
import { WorkbenchProvider } from './workbench'

export function App() {
  // ★ 当前工作台/面板来自 URL（hash 路由，URL 是唯一数据源）：刷新保持、可分享、可前进后退。
  const { workbench, activeId, selectPanel, selectWorkbench } = useActivePanel()

  // 全局状态只请求一次，顶栏与状态栏共用（避免重复打后端）。
  const status = useAppStatus()

  // 注册表是外部可变状态：setEnabledModules 后递增一次版本号，让导航/工作区按新可用性重渲染。
  const [, setAvailabilityVersion] = useState(0)

  useEffect(() => {
    // online 有模块数据 ⇒ 用已启用模块 id；loading/offline ⇒ null（状态未知，一律可用，不因不知道就全灰）。
    if (status.state === 'online') {
      setEnabledModules(status.modules.filter((m) => m.enabled).map((m) => m.id))
    } else {
      setEnabledModules(null)
    }
    setAvailabilityVersion((v) => v + 1)
  }, [status.state, status.modules])

  const active: PanelPlugin | undefined = panelRegistry.query(activeId)
  const ActiveComponent = active?.component
  // ★ 不可用也不改选（仍停在它），只把工作区换成占位提示（不空白、不报错）。
  const activeAvailable = active !== undefined && isAvailable(active)

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-app text-fg">
      <TopBar
        connection={status.state}
        workbench={workbench}
        onSelectWorkbench={selectWorkbench}
      />

      <WorkbenchProvider value={workbench}>
        <div className="flex min-h-0 flex-1">
          <SideNav workbench={workbench} activeId={activeId} onSelect={selectPanel} />

          <main className="min-w-0 flex-1 overflow-auto p-4">
            {ActiveComponent ? (
              activeAvailable ? (
                // ★ 面板级错误边界：任何一个面板渲染崩溃都只影响它自己，不许把整个控制台打白。
                //   key=activeId ⇒ 切面板时边界重建、错误状态自动复位。
                <PanelErrorBoundary key={activeId} label={active?.manifest.name}>
                  <ActiveComponent />
                </PanelErrorBoundary>
              ) : (
                // 模块停用 ⇒ 入口置灰且当前工作区给占位提示（不空白、不报错、不改选）。
                <div className="flex h-full items-center justify-center px-4 text-center text-dim">
                  <span>
                    该面板所属模块{' '}
                    <span className="mono">{active?.manifest.moduleId}</span>{' '}
                    未启用 —— 去「控制台」里启用它
                  </span>
                </div>
              )
            ) : (
              <div className="flex h-full items-center justify-center text-dim">请注册至少一个面板</div>
            )}
          </main>
        </div>
      </WorkbenchProvider>

      <StatusBar status={status} />
    </div>
  )
}
