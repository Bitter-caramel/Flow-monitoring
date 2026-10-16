/**
 * 左导航（LayerNav）—— 按层分组的面板导航。
 *
 * 设计文档 §4 / §9 P0：左导航**按 L0~L3 分层**。
 * ★ 数据源是注册表真实的分组能力 panelRegistry.listByLayer()（按 manifest.layer 分组），
 *   本组件不自己另造分组逻辑，也不猜层号。
 *
 * 规则：
 *   - 固定渲染 L0 / L1 / L2 / L3 四组（顺序 L0→L3），组标题形如 `L2 功能 (2)`；
 *   - **空组如实置灰、不可点**（不隐藏 —— 这样"分层"是看得见的，而不是靠伪造空层）；
 *   - 组内按面板**名字升序**；面板项显示 名称 + 版本（等宽）；
 *   - 选中态 / hover 用语义令牌；
 *   - 键盘（设计文档 §1"键盘优先"）：↑/↓ 在可见面板间移动、Enter 选中（Home/End 到首尾）。
 */
import { useRef, useState } from 'react'
import { panelRegistry } from './registry'
import type { PanelPlugin } from './registry'
import type { PanelLayer } from './manifest'

/** 固定四层顺序（对齐后端 registry.Layer：L0 内核 → L1 基础 → L2 功能 → L3 扩展）。 */
const LAYER_ORDER: readonly PanelLayer[] = ['L0', 'L1', 'L2', 'L3']

/** 层中文名。 */
const LAYER_NAME: Record<PanelLayer, string> = {
  L0: '内核',
  L1: '基础',
  L2: '功能',
  L3: '扩展',
}

interface LayerNavProps {
  activeId: string
  onSelect: (id: string) => void
}

/** 组内按显示名升序（中文用 localeCompare('zh') 稳定排序）。 */
function sortByName(panels: PanelPlugin[]): PanelPlugin[] {
  return [...panels].sort((a, b) => a.manifest.name.localeCompare(b.manifest.name, 'zh'))
}

export function LayerNav({ activeId, onSelect }: LayerNavProps) {
  // ★ 真实分组：注册表按 layer 分组（Map<PanelLayer, PanelPlugin[]>）。
  const groups = panelRegistry.listByLayer()
  const byLayer = new Map<PanelLayer, PanelPlugin[]>()
  for (const layer of LAYER_ORDER) {
    byLayer.set(layer, sortByName(groups.get(layer) ?? []))
  }

  // 可见面板的扁平顺序（L0→L3、组内按名升序）—— 键盘移动与 roving tabindex 的基础。
  const ordered: PanelPlugin[] = LAYER_ORDER.flatMap((layer) => byLayer.get(layer) ?? [])

  const [cursor, setCursor] = useState(() => {
    const i = ordered.findIndex((p) => p.manifest.id === activeId)
    return i >= 0 ? i : 0
  })
  const itemRefs = useRef<(HTMLButtonElement | null)[]>([])

  function focusItem(index: number) {
    if (ordered.length === 0) return
    const clamped = Math.min(Math.max(index, 0), ordered.length - 1)
    setCursor(clamped)
    itemRefs.current[clamped]?.focus()
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLElement>) {
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault()
        focusItem(cursor + 1)
        break
      case 'ArrowUp':
        e.preventDefault()
        focusItem(cursor - 1)
        break
      case 'Home':
        e.preventDefault()
        focusItem(0)
        break
      case 'End':
        e.preventDefault()
        focusItem(ordered.length - 1)
        break
      case 'Enter': {
        e.preventDefault()
        const picked = ordered[cursor]
        if (picked) onSelect(picked.manifest.id)
        break
      }
      default:
        break
    }
  }

  let flatIndex = -1
  return (
    <aside className="flex w-[220px] min-w-[220px] shrink-0 flex-col overflow-y-auto border-r border-subtle bg-panel">
      <nav aria-label="面板导航" className="flex flex-1 flex-col gap-3 p-2" onKeyDown={onKeyDown}>
        {LAYER_ORDER.map((layer) => {
          const panels = byLayer.get(layer) ?? []
          const empty = panels.length === 0
          return (
            <section key={layer} role="group" aria-label={`${layer} ${LAYER_NAME[layer]}`}>
              <div
                className={`px-2 py-1 text-xs font-semibold tracking-wide ${
                  empty ? 'text-dim opacity-60' : 'text-muted'
                }`}
              >
                <span className="mono">{layer}</span> {LAYER_NAME[layer]}{' '}
                <span className="mono">({panels.length})</span>
              </div>

              {empty ? (
                <div className="select-none px-2 py-1 text-xs text-dim opacity-50">（空）</div>
              ) : (
                <ul className="flex flex-col gap-0.5">
                  {panels.map((p) => {
                    flatIndex += 1
                    const idx = flatIndex
                    const active = p.manifest.id === activeId
                    return (
                      <li key={p.manifest.id}>
                        <button
                          type="button"
                          ref={(el) => {
                            itemRefs.current[idx] = el
                          }}
                          tabIndex={idx === cursor ? 0 : -1}
                          aria-current={active ? 'page' : undefined}
                          title={p.manifest.description}
                          onClick={() => onSelect(p.manifest.id)}
                          onFocus={() => setCursor(idx)}
                          className={`flex w-full items-center gap-2 rounded-xs px-2 py-1.5 text-left text-base ${
                            active ? 'bg-accent text-accent-fg' : 'text-fg hover:bg-elevated'
                          }`}
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
              )}
            </section>
          )
        })}
      </nav>
    </aside>
  )
}
