/**
 * 顶栏（TopBar）。
 *
 * 设计文档 §4 四区骨架的第一区：
 *   产品名 │ 全局搜索（Ctrl+K，占位）│ 主题切换 │ 密度切换 │ 连接指示
 *
 * 本轮范围（12-4b-2）：
 *   - 全局搜索只做"占位输入框"（placeholder 写明 Ctrl+K，命令面板 P3 实现）；
 *   - 主题（深/浅）与密度（compact/normal/comfortable）真实可切换，
 *     写 documentElement.dataset 并持久化（见 ./theme.ts）；
 *   - 连接指示只读 useAppStatus 的三态，不在此处发起请求。
 *
 * ★ 只用语义令牌/语义工具类，不写死颜色；图标用字符。
 */
import { useState } from 'react'
import {
  DENSITIES,
  DENSITY_LABELS,
  readStoredDensity,
  readStoredTheme,
  setDensity,
  setTheme,
  type Density,
  type Theme,
} from './theme'
import { WORKBENCHES, WORKBENCH_LABELS, type Workbench } from './manifest'
import type { ConnectionState } from './useAppStatus'

interface TopBarProps {
  /** 后端连接状态（由 App 的 useAppStatus 传入）。 */
  connection: ConnectionState
  /** 当前工作台（由 App 的 useActivePanel 传入）。 */
  workbench: Workbench
  /** 切换工作台（跳到该工作台的默认面板）。 */
  onSelectWorkbench: (wb: Workbench) => void
}

/** 连接指示的文案与配色（都用语义令牌）。 */
function connectionView(connection: ConnectionState): { dot: string; text: string; label: string } {
  switch (connection) {
    case 'online':
      return { dot: 'bg-ok', text: 'text-ok', label: '在线' }
    case 'offline':
      return { dot: 'bg-danger', text: 'text-danger', label: '未连接' }
    default:
      return { dot: 'bg-dim', text: 'text-dim', label: '连接中…' }
  }
}

export function TopBar({ connection, workbench, onSelectWorkbench }: TopBarProps) {
  const [theme, setThemeState] = useState<Theme>(() => readStoredTheme())
  const [density, setDensityState] = useState<Density>(() => readStoredDensity())

  function toggleTheme() {
    const next: Theme = theme === 'dark' ? 'light' : 'dark'
    setTheme(next)
    setThemeState(next)
  }

  function changeDensity(next: Density) {
    setDensity(next)
    setDensityState(next)
  }

  const conn = connectionView(connection)

  return (
    <header className="flex h-11 shrink-0 items-center gap-3 border-b border-subtle bg-panel px-3">
      <span className="text-md font-semibold text-fg">流量分析平台</span>

      {/* 工作台 tab：静态分析 / 动态分析 / 控制台（当前工作台高亮） */}
      <nav aria-label="工作台" className="flex items-center gap-1">
        {WORKBENCHES.map((wb) => {
          const active = wb === workbench
          return (
            <button
              key={wb}
              type="button"
              onClick={() => onSelectWorkbench(wb)}
              aria-current={active ? 'page' : undefined}
              className={`rounded-sm px-2 py-1 text-sm ${
                active
                  ? 'bg-accent text-accent-fg'
                  : 'text-muted hover:bg-elevated hover:text-fg'
              }`}
            >
              {WORKBENCH_LABELS[wb]}
            </button>
          )
        })}
      </nav>

      {/* 全局搜索：本轮仅占位，命令面板 P3 实现 */}
      <input
        type="search"
        readOnly
        placeholder="Ctrl+K（P3 实现）"
        aria-label="全局搜索（命令面板，P3 实现）"
        title="命令面板将在 P3 实现"
        className="h-7 w-64 max-w-[40vw] rounded-sm border border-subtle bg-app px-2 text-sm text-fg placeholder:text-dim focus:border-strong focus:outline-none"
      />

      <div className="ml-auto flex items-center gap-3">
        {/* 主题切换：深 / 浅 */}
        <button
          type="button"
          onClick={toggleTheme}
          title="切换主题（深/浅）"
          aria-label={`切换主题，当前 ${theme === 'dark' ? '深色' : '浅色'}`}
          className="rounded-sm border border-subtle bg-elevated px-2 py-1 text-sm text-muted hover:border-strong hover:text-fg"
        >
          {theme === 'dark' ? '☾ 深色' : '☀ 浅色'}
        </button>

        {/* 密度切换：三档 */}
        <label className="flex items-center gap-1.5 text-sm text-muted">
          密度
          <select
            value={density}
            onChange={(e) => changeDensity(e.target.value as Density)}
            title="切换密度（表格/列表行高随之变化）"
            aria-label="切换密度"
            className="rounded-sm border border-subtle bg-app px-1.5 py-1 text-sm text-fg focus:border-strong focus:outline-none"
          >
            {DENSITIES.map((d) => (
              <option key={d} value={d}>
                {DENSITY_LABELS[d]}
              </option>
            ))}
          </select>
        </label>

        {/* 连接指示 */}
        <span className={`flex items-center gap-1.5 text-sm ${conn.text}`} title="后端连接状态">
          <span className={`inline-block h-1.5 w-1.5 rounded-full ${conn.dot}`} aria-hidden="true" />
          {conn.label}
        </span>
      </div>
    </header>
  )
}
