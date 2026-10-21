/**
 * 当前工作台 + 当前面板 —— hash 路由。
 *
 * ★ 约定：URL 是唯一数据源（single source of truth）。
 *   当前状态由 `window.location.hash` 决定，规范形如 `#/<workbench>/<面板 id>`
 *   （如 `#/live/panels.alert-list`）。
 *   组件不自己存"当前面板"，只读本 hook 返回的 `workbench` / `activeId`；
 *   切换面板 = 写 hash（产生一条历史记录）；hash 变化 = 唯一的更新入口。
 *   ⇒ 刷新保持、URL 可分享、浏览器前进/后退可在面板间切换。
 *
 * 兼容旧格式（只解析，随后 replaceState 规范化，不新增历史记录）：
 *   - `#/panel/<id>` ⇒ 用该面板的 `workbenches[0]` 推断工作台；
 *   - 裸 `#<id>`       ⇒ 同上。
 *   - 若 hash 里的工作台与面板归类不符 ⇒ 以面板归类（`workbenches[0]`）为准并纠正；
 *   - 非法/空 ⇒ 回落到「静态分析 + panels.capture-import」。
 *
 * 设计约束：
 *   - 不引入任何路由依赖（react-router 等），只用原生 hash；
 *   - `selectPanel` / `selectWorkbench` 只写 `location.hash`，不直接 setState ——
 *     保证"URL 是唯一数据源"，状态由 `hashchange` 监听统一更新；
 *   - 所有规范化一律用 `history.replaceState`，只有用户主动切换才产生历史记录；
 *   - 非法/空 hash 回落到默认值，不抛异常、不白屏。
 */
import { useCallback, useEffect, useState } from 'react'
import { panelRegistry } from './registry'
import type { Workbench } from './manifest'

/** 旧规范 hash 前缀：`#/panel/<id>`（仅用于兼容解析）。 */
export const PANEL_HASH_PREFIX = '#/panel/'

/** 默认工作台：非法/空 hash 的回落目标。 */
export const DEFAULT_WORKBENCH: Workbench = 'static'

/** 各工作台的默认面板（点击工作台 tab 时跳到这里）。 */
export const WORKBENCH_DEFAULT_PANEL: Record<Workbench, string> = {
  static: 'panels.capture-import',
  live: 'panels.alert-list',
  console: 'panels.module-graph',
}

/** 一次解析得到的路由状态。 */
interface Route {
  workbench: Workbench
  activeId: string
}

/** 解析结果 + 是否需要 replaceState 规范化 URL。 */
interface ParsedRoute {
  route: Route
  normalize: boolean
}

/** 是否合法工作台。 */
function isWorkbench(value: string): value is Workbench {
  return value === 'static' || value === 'live' || value === 'console'
}

/** 规范化 URL：`#/<workbench>/<panelId>`。 */
function hashFor(route: Route): string {
  return `#/${route.workbench}/${route.activeId}`
}

/** 某工作台的默认面板；默认面板不存在时退回该工作台注册顺序里的第一个。 */
function defaultPanelFor(wb: Workbench): Route | null {
  const preferred = WORKBENCH_DEFAULT_PANEL[wb]
  const plugin = panelRegistry.query(preferred)
  if (plugin && plugin.manifest.workbenches.includes(wb)) {
    return { workbench: wb, activeId: preferred }
  }
  const first = panelRegistry.listByWorkbench(wb)[0]
  return first ? { workbench: wb, activeId: first.manifest.id } : null
}

/** 非法/空 hash 的回落：静态分析 + 抓包导入；注册表异常时再退回第一个可用面板。 */
function fallbackRoute(normalize: boolean): ParsedRoute {
  const preferred = defaultPanelFor(DEFAULT_WORKBENCH)
  if (preferred) return { route: preferred, normalize }

  const first = panelRegistry.list()[0]
  if (!first) {
    return { route: { workbench: DEFAULT_WORKBENCH, activeId: '' }, normalize: false }
  }
  return {
    route: {
      workbench: first.manifest.workbenches[0] ?? DEFAULT_WORKBENCH,
      activeId: first.manifest.id,
    },
    normalize,
  }
}

/**
 * 把面板 id 解析成路由。
 *   - requested 有值且面板归类包含它 ⇒ 采用 requested；
 *   - 否则以面板归类 `workbenches[0]` 为准（必要时需要 replaceState 纠正）；
 *   - forceNormalize 用于旧格式（`#/panel/<id>` / 裸 `#<id>`）⇒ 一律规范化。
 */
function routeForPanel(id: string, requested: Workbench | undefined, forceNormalize: boolean): ParsedRoute {
  const plugin = panelRegistry.query(id)
  if (!plugin) return fallbackRoute(true)

  const allowed = plugin.manifest.workbenches
  const workbench =
    requested !== undefined && allowed.includes(requested) ? requested : allowed[0]
  if (!workbench) return fallbackRoute(true)

  return {
    route: { workbench, activeId: id },
    normalize: forceNormalize || (requested !== undefined && workbench !== requested),
  }
}

/** 从当前 `location.hash` 解析路由。 */
function parseHash(): ParsedRoute {
  const hash = window.location.hash
  if (!hash || hash === '#') return fallbackRoute(true)

  // 去掉前导 '#'，并容忍尾随斜杠。
  const raw = hash.slice(1).replace(/\/+$/, '')
  if (raw === '' || raw === '/') return fallbackRoute(true)

  // '/static/<id>' → ['static', '<id>']；'<id>' → ['<id>']
  const segments = (raw.startsWith('/') ? raw.slice(1) : raw).split('/')

  // 旧格式 '#/panel/<id>'
  if (segments[0] === 'panel') {
    const id = segments.slice(1).join('/').trim()
    return id ? routeForPanel(id, undefined, true) : fallbackRoute(true)
  }

  // 新格式 '#/<workbench>/<id>'
  if (isWorkbench(segments[0])) {
    const requested = segments[0]
    const id = segments.slice(1).join('/').trim()
    return id ? routeForPanel(id, requested, false) : fallbackRoute(true)
  }

  // 裸 '#<id>'（旧格式）
  const id = raw.trim()
  return id ? routeForPanel(id, undefined, true) : fallbackRoute(true)
}

/** 当前工作台/面板 + 切换函数（见文件头：URL 是唯一数据源）。 */
export function useActivePanel(): {
  workbench: Workbench
  activeId: string
  selectPanel: (id: string) => void
  selectWorkbench: (wb: Workbench) => void
} {
  // 初值：解析 URL；非法/空 ⇒ 回落到默认值（绝不抛异常 / 白屏）。
  const [route, setRoute] = useState<Route>(() => parseHash().route)

  // 首帧补全/规范化 URL：一律 replaceState（不新增历史记录）。
  useEffect(() => {
    const parsed = parseHash()
    if (parsed.normalize && parsed.route.activeId) {
      window.history.replaceState(null, '', hashFor(parsed.route))
    }
  }, [])

  // 监听 hash：URL 变化 ⇒ 重新解析 ⇒ 状态跟着 URL 走（URL 是唯一数据源）。
  useEffect(() => {
    function onHashChange() {
      const parsed = parseHash()
      setRoute(parsed.route)
      // 兼容旧格式 / 工作台归类不符时纠正 URL，但不新增历史记录。
      if (parsed.normalize && parsed.route.activeId) {
        window.history.replaceState(null, '', hashFor(parsed.route))
      }
    }
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  // 切换面板：优先留在当前工作台（packet-list 等跨工作台面板不会被强行跳走），
  // 当前工作台不包含该面板时退到它的第一个工作台。
  const selectPanel = useCallback((id: string) => {
    const plugin = panelRegistry.query(id)
    if (!plugin) return
    const current = parseHash().route.workbench
    const allowed = plugin.manifest.workbenches
    const workbench = allowed.includes(current) ? current : allowed[0]
    if (!workbench) return
    window.location.hash = hashFor({ workbench, activeId: id })
  }, [])

  // 切换工作台：跳到该工作台的默认面板（写 hash ⇒ 产生一条历史记录）。
  const selectWorkbench = useCallback((wb: Workbench) => {
    const target = defaultPanelFor(wb)
    if (!target) return
    window.location.hash = hashFor(target)
  }, [])

  return {
    workbench: route.workbench,
    activeId: route.activeId,
    selectPanel,
    selectWorkbench,
  }
}
