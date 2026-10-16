import { useState } from 'react'
import { panelRegistry } from './registry'
import type { PanelPlugin } from './registry'

/**
 * Shell 外壳。
 *
 * 只做两件事：
 *   1. 读面板注册表，渲染导航（面板列表）
 *   2. 在容器区挂载选中的面板组件
 *
 * shell 不感知具体面板实现 —— 新增/替换面板只需注册，无需改 shell。
 */
export function App() {
  const panels = panelRegistry.list()
  const [activeId, setActiveId] = useState<string>(panels[0]?.manifest.id ?? '')

  const active: PanelPlugin | undefined = panelRegistry.query(activeId)
  const ActiveComponent = active?.component

  return (
    <div className="flex h-screen overflow-hidden bg-app text-fg">
      <aside className="flex w-[220px] min-w-[220px] flex-col border-r border-subtle bg-panel">
        <div className="border-b border-subtle px-4 py-3 text-lg font-semibold">流量分析平台</div>
        <nav className="flex flex-1 flex-col gap-1 overflow-y-auto p-2">
          {panels.map((p) => (
            <button
              key={p.manifest.id}
              className={`flex items-center gap-2 rounded-xs px-2.5 py-2 text-left text-base ${
                p.manifest.id === activeId ? 'bg-accent text-accent-fg' : 'hover:bg-elevated'
              }`}
              onClick={() => setActiveId(p.manifest.id)}
              title={p.manifest.description}
            >
              <span className="w-[18px] text-center">{p.manifest.icon ?? '▫'}</span>
              <span className="flex-1">{p.manifest.name}</span>
              <span className={`text-xs ${p.manifest.id === activeId ? 'text-accent-fg/70' : 'text-dim'}`}>
                v{p.manifest.version}
              </span>
            </button>
          ))}
        </nav>
        <div className="border-t border-subtle px-3 py-2 text-xs text-dim">{panels.length} 个面板已注册</div>
      </aside>

      <main className="flex-1 overflow-auto p-4">
        {ActiveComponent ? (
          <ActiveComponent />
        ) : (
          <div className="flex h-full items-center justify-center text-dim">请注册至少一个面板</div>
        )}
      </main>
    </div>
  )
}
