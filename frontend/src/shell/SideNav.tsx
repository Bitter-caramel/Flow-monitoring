/**
 * 左导航（SideNav）—— 按工作台 + 工作台内分组的面板导航。
 *
 * ★ 数据源是注册表真实的分组能力 panelRegistry.listByWorkbench(workbench)
 *   （按 manifest.workbenches 过滤，保持注册顺序），本组件不自己另造工作台归属。
 *
 * 规则：
 *   - 只列当前工作台的面板；
 *   - 面板有 manifest.group ⇒ 按 group 显示分组标题；无 group 归入「其它」（排在最后）；
 *   - 模块未启用 ⇒ 置灰（不隐藏：让"能力存在但没开"可见），工作区给占位提示；
 *   - 选中态 / hover 用语义令牌；
 *   - 键盘（设计文档 §1"键盘优先"）：↑/↓ 在可见面板间移动、Enter 选中（Home/End 到首尾）。
 */
import { useEffect, useRef, useState } from 'react'
import { isAvailable, panelRegistry } from './registry'
import type { PanelPlugin } from './registry'
import { WORKBENCH_LABELS, type Workbench } from './manifest'

/** 无 group 的面板归入该分组。 */
const OTHER_GROUP = '其它'

interface SideNavProps {
  /** 当前工作台（由 App 的 useActivePanel 传入）。 */
  workbench: Workbench
  activeId: string
  onSelect: (id: string) => void
}

interface NavGroup {
  title: string
  panels: PanelPlugin[]
}

/** 按 manifest.group 分组；保持注册顺序，「其它」永远排最后。 */
function groupPanels(panels: PanelPlugin[]): NavGroup[] {
  const groups = new Map<string, PanelPlugin[]>()
  const order: string[] = []
  for (const panel of panels) {
    const title = panel.manifest.group?.trim() || OTHER_GROUP
    let items = groups.get(title)
    if (!items) {
      items = []
      groups.set(title, items)
      order.push(title)
    }
    items.push(panel)
  }
  // 「其它」是无 group 面板的兜底分组：即使它在注册顺序中靠前，也排到最后。
  const otherIndex = order.indexOf(OTHER_GROUP)
  if (otherIndex >= 0) {
    order.splice(otherIndex, 1)
    order.push(OTHER_GROUP)
  }
  return order.map((title) => ({ title, panels: groups.get(title) ?? [] }))
}

export function SideNav({ workbench, activeId, onSelect }: SideNavProps) {
  // ★ 真实数据：注册表按工作台过滤（保持注册顺序）。
  const groups = groupPanels(panelRegistry.listByWorkbench(workbench))

  // 可见面板的扁平顺序（组顺序、组内注册顺序）—— 键盘移动与 roving tabindex 的基础。
  const ordered: PanelPlugin[] = groups.flatMap((g) => g.panels)

  const [cursor, setCursor] = useState(() => {
    // 初始光标优先停在当前面板；若它不可用（所属模块停用），退到第一个可用项，
    // 避免 roving tabindex 落到 disabled 按钮上，导致键盘无法进入导航。
    const i = ordered.findIndex((p) => p.manifest.id === activeId)
    if (i >= 0 && isAvailable(ordered[i])) return i
    const first = ordered.findIndex((p) => isAvailable(p))
    return first >= 0 ? first : 0
  })
  const itemRefs = useRef<(HTMLButtonElement | null)[]>([])

  // 路由变化（工作台 tab / 前进后退）后，把键盘光标同步到当前面板，避免 roving tabindex 停在旧位置。
  useEffect(() => {
    const i = ordered.findIndex((p) => p.manifest.id === activeId)
    if (i >= 0 && isAvailable(ordered[i])) setCursor(i)
    // ordered 每次渲染都会重建；用 activeId + workbench 作为"路由变化"信号即可。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeId, workbench])

  /** 某个下标的条目当前是否可用（越界视为不可用）。 */
  function usableAt(index: number): boolean {
    const p = ordered[index]
    return p !== undefined && isAvailable(p)
  }

  // 有效光标：只落在可用项上；可用性变化令原 cursor 失效时，本次渲染回退到第一个可用项。
  const effectiveCursor = usableAt(cursor) ? cursor : ordered.findIndex((p) => isAvailable(p))

  /** 从 from 出发沿 dir 找下一个可用项（不越过首尾，找不到返回 -1）。 */
  function findAvailable(from: number, dir: 1 | -1): number {
    for (let i = from + dir; i >= 0 && i < ordered.length; i += dir) {
      if (isAvailable(ordered[i])) return i
    }
    return -1
  }

  function focusItem(index: number) {
    if (index < 0 || index >= ordered.length) return
    setCursor(index)
    itemRefs.current[index]?.focus()
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLElement>) {
    switch (e.key) {
      case 'ArrowDown': {
        e.preventDefault()
        if (effectiveCursor < 0) break
        const next = findAvailable(effectiveCursor, 1)
        if (next >= 0) focusItem(next) // 找不到就停在原地，绝不停到灰条目上
        break
      }
      case 'ArrowUp': {
        e.preventDefault()
        if (effectiveCursor < 0) break
        const prev = findAvailable(effectiveCursor, -1)
        if (prev >= 0) focusItem(prev)
        break
      }
      case 'Home': {
        e.preventDefault()
        const first = ordered.findIndex((p) => isAvailable(p))
        if (first >= 0) focusItem(first)
        break
      }
      case 'End': {
        e.preventDefault()
        let last = -1
        for (let i = ordered.length - 1; i >= 0; i -= 1) {
          if (isAvailable(ordered[i])) {
            last = i
            break
          }
        }
        if (last >= 0) focusItem(last)
        break
      }
      case 'Enter': {
        e.preventDefault()
        const picked = ordered[effectiveCursor]
        if (picked && isAvailable(picked)) onSelect(picked.manifest.id)
        break
      }
      default:
        break
    }
  }

  let flatIndex = -1
  return (
    <aside className="flex w-[220px] min-w-[220px] shrink-0 flex-col overflow-y-auto border-r border-subtle bg-panel">
      <nav
        aria-label={`${WORKBENCH_LABELS[workbench]}面板导航`}
        className="flex flex-1 flex-col gap-3 p-2"
        onKeyDown={onKeyDown}
      >
        {groups.length === 0 ? (
          <div className="select-none px-2 py-1 text-xs text-dim opacity-50">（空）</div>
        ) : (
          groups.map((group) => (
            <section key={group.title} role="group" aria-label={group.title}>
              <div className="px-2 py-1 text-xs font-semibold tracking-wide text-muted">
                {group.title} <span className="mono">({group.panels.length})</span>
              </div>

              <ul className="flex flex-col gap-0.5">
                {group.panels.map((p) => {
                  flatIndex += 1
                  const idx = flatIndex
                  const active = p.manifest.id === activeId
                  const available = isAvailable(p)
                  // 模块停用 ⇒ 置灰 + 不可点（不隐藏：让"能力存在但没开"可见）。
                  return (
                    <li key={p.manifest.id}>
                      <button
                        type="button"
                        ref={(el) => {
                          itemRefs.current[idx] = el
                        }}
                        tabIndex={idx === effectiveCursor ? 0 : -1}
                        aria-current={active ? 'page' : undefined}
                        disabled={!available}
                        title={
                          available
                            ? p.manifest.description
                            : `模块 ${p.manifest.moduleId ?? ''} 未启用`
                        }
                        onClick={() => onSelect(p.manifest.id)}
                        onFocus={() => setCursor(idx)}
                        className={`flex w-full items-center gap-2 rounded-xs px-2 py-1.5 text-left text-base ${
                          active
                            ? 'bg-accent text-accent-fg'
                            : available
                              ? 'text-fg hover:bg-elevated'
                              : 'text-fg'
                        } ${available ? '' : 'cursor-not-allowed opacity-60'}`}
                      >
                        <span className="w-[18px] text-center">{p.manifest.icon ?? '▫'}</span>
                        <span className="flex-1 truncate">{p.manifest.name}</span>
                        <span className={`mono ${active ? 'opacity-70' : 'text-dim'}`}>
                          v{p.manifest.version}
                        </span>
                      </button>
                    </li>
                  )
                })}
              </ul>
            </section>
          ))
        )}
      </nav>
    </aside>
  )
}
