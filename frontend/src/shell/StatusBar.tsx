/**
 * 底部状态栏（StatusBar）。
 *
 * 设计文档 §4 四区骨架的第四区；§6 组件清单要求其"与后端 health/selfcheck 对接"。
 *
 * ★ 真读后端（不许 mock）：
 *   - GET /api/modules            ⇒ `模块 N · 启用 M`
 *   - GET /api/modules/selfcheck  ⇒ 自检结论（通过 / 有问题：错误数 + 警告数）
 *   数据与超时/错误处理都在 useAppStatus（经 src/api.ts）。
 *
 * ★ 连接语义（如实呈现，不伪造）：
 *   - loading ⇒ "连接后端…"
 *   - online  ⇒ 显示真实计数与自检结论
 *   - offline ⇒ "后端未连接"（接口不可用/超时 3s 时），**绝不显示假模块数**
 *   右上角提供手动刷新。
 */
import type { ReactNode } from 'react'
import type { AppStatus } from './useAppStatus'
import type { SelfCheckReport } from '../api'

interface StatusBarProps {
  status: AppStatus
}

/** 自检结论文案。 */
function selfCheckView(report: SelfCheckReport | null): ReactNode {
  if (!report) {
    return <span className="text-dim">自检：不可用</span>
  }
  if (report.ok) {
    return <span className="text-ok">自检：通过</span>
  }
  const errors = report.errors?.length ?? 0
  const warnings = report.warnings?.length ?? 0
  return (
    <span className="text-warn">
      自检：有问题（错误 <span className="mono">{errors}</span> · 警告{' '}
      <span className="mono">{warnings}</span>）
    </span>
  )
}

export function StatusBar({ status }: StatusBarProps) {
  const { state, modules, selfcheck, error, lastUpdated, refreshing, refresh } = status

  let main: ReactNode
  if (state === 'loading') {
    main = <span className="text-dim">连接后端…</span>
  } else if (state === 'offline') {
    main = (
      <span className="text-danger" title={error || '后端接口不可用或超时（3s）'}>
        后端未连接
      </span>
    )
  } else {
    const total = modules.length
    const enabled = modules.filter((m) => m.enabled).length
    main = (
      <>
        <span>
          模块 <span className="mono">{total}</span> · 启用 <span className="mono">{enabled}</span>
        </span>
        <span className="text-dim">·</span>
        {selfCheckView(selfcheck)}
      </>
    )
  }

  return (
    <footer className="flex h-7 shrink-0 items-center gap-3 border-t border-subtle bg-panel px-3 text-xs text-muted">
      {main}
      <div className="ml-auto flex items-center gap-3">
        {lastUpdated !== null && (
          <span className="mono text-dim" title="上次成功读取后端的时刻">
            {new Date(lastUpdated).toLocaleTimeString('zh-CN', { hour12: false })}
          </span>
        )}
        <button
          type="button"
          onClick={refresh}
          disabled={refreshing}
          title="手动刷新后端状态"
          className="rounded-xs border border-subtle px-2 py-0.5 text-xs text-muted hover:border-strong hover:text-fg disabled:opacity-50"
        >
          {refreshing ? '刷新中…' : '刷新'}
        </button>
      </div>
    </footer>
  )
}
