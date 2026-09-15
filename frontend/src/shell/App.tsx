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
    <div className="app">
      <aside className="sidebar">
        <div className="brand">流量分析平台</div>
        <nav className="nav">
          {panels.map((p) => (
            <button
              key={p.manifest.id}
              className={`nav-item ${p.manifest.id === activeId ? 'active' : ''}`}
              onClick={() => setActiveId(p.manifest.id)}
              title={p.manifest.description}
            >
              <span className="nav-icon">{p.manifest.icon ?? '▫'}</span>
              <span className="nav-name">{p.manifest.name}</span>
              <span className="nav-version">v{p.manifest.version}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">{panels.length} 个面板已注册</div>
      </aside>

      <main className="content">
        {ActiveComponent ? (
          <ActiveComponent />
        ) : (
          <div className="empty">请注册至少一个面板</div>
        )}
      </main>
    </div>
  )
}
