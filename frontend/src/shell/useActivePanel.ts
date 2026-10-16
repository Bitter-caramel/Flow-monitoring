/**
 * 当前面板（active panel）—— hash 路由。
 *
 * ★ 约定：URL 是唯一数据源（single source of truth）。
 *   当前面板由 `window.location.hash` 决定，形如 `#/panel/<面板 id>`（也容忍裸 `#<id>`）。
 *   组件不自己存"当前面板"，只读本 hook 返回的 `activeId`；
 *   切换面板 = 写 hash（产生一条历史记录）；hash 变化 = 唯一的更新入口。
 *   ⇒ 刷新保持、URL 可分享、浏览器前进/后退可在面板间切换。
 *
 * 设计约束：
 *   - 不引入任何路由依赖（react-router 等），只用原生 hash；
 *   - `select` 只写 `location.hash`，不直接 setState —— 保证"URL 是唯一数据源"，
 *     `activeId` 永远由 `hashchange` 监听统一驱动；
 *   - 非法/空 hash 一律回落到第一个面板（`panelRegistry.list()[0]`），不抛异常、不白屏；
 *   - 首帧用 `history.replaceState` 补全 URL（不是 pushState，避免多出一条历史记录），
 *     这样任何时候复制地址栏 URL 都能还原界面。
 */
import { useCallback, useEffect, useState } from 'react'
import { panelRegistry } from './registry'

/** 规范 hash 前缀：`#/panel/<id>`。 */
export const PANEL_HASH_PREFIX = '#/panel/'

/** 从当前 `location.hash` 解析出候选面板 id；无法识别时返回 ''。 */
function readPanelIdFromHash(): string {
  const hash = window.location.hash
  if (!hash || hash === '#') return ''
  // 去掉前导 '#'：'#/panel/<id>' → '/panel/<id>'，'#<id>' → '<id>'
  const raw = hash.slice(1)
  // 优先识别规范形式 '#/panel/<id>'，同时容忍裸 '#<id>'
  const id = raw.startsWith('/panel/') ? raw.slice('/panel/'.length) : raw
  // 容忍尾随斜杠（'#/panel/<id>/'）
  return id.replace(/\/+$/, '').trim()
}

/** 候选 id 是否已在注册表中注册（空串视为未注册）。 */
function isRegistered(id: string): boolean {
  return id !== '' && panelRegistry.query(id) !== undefined
}

/** 回落面板：注册表第一个（list() 按 id 稳定排序）；注册表为空时 ''。 */
function firstPanelId(): string {
  return panelRegistry.list()[0]?.manifest.id ?? ''
}

/** 当前面板 + 切换函数（见文件头：URL 是唯一数据源）。 */
export function useActivePanel(): {
  activeId: string
  select: (id: string) => void
} {
  // 初值：解析 URL；非法/空 ⇒ 回落到第一个面板（绝不抛异常 / 白屏）。
  const [activeId, setActiveId] = useState<string>(() => {
    const fromHash = readPanelIdFromHash()
    return isRegistered(fromHash) ? fromHash : firstPanelId()
  })

  // 首帧补全 URL：hash 为空/非法时，用 replaceState 把地址补成当前面板。
  // ★ 用 replaceState 而非 pushState：不新增历史记录（否则首次后退会先回到空 hash）。
  useEffect(() => {
    const fromHash = readPanelIdFromHash()
    if (isRegistered(fromHash)) return
    const fallback = firstPanelId()
    if (!fallback) return
    window.history.replaceState(null, '', `${PANEL_HASH_PREFIX}${fallback}`)
  }, [])

  // 监听 hash：URL 变化 ⇒ 重新解析 ⇒ activeId 跟着 URL 走（URL 是唯一数据源）。
  useEffect(() => {
    function onHashChange() {
      const fromHash = readPanelIdFromHash()
      setActiveId(isRegistered(fromHash) ? fromHash : firstPanelId())
    }
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  // 切换：只改 hash（产生一条历史记录 ⇒ 浏览器前进/后退可切面板）。
  // 不直接 setState；activeId 由上面的 hashchange 监听统一更新。
  const select = useCallback((id: string) => {
    window.location.hash = `${PANEL_HASH_PREFIX}${id}`
  }, [])

  return { activeId, select }
}
