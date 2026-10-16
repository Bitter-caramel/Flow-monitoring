/**
 * 全局状态读取（顶栏连接指示 + 底部状态栏共用）。
 *
 * ★ 真读后端（不许 mock）：
 *   - GET /api/modules            ⇒ 模块数 / 启用数
 *   - GET /api/modules/selfcheck  ⇒ 自检结论
 *   两个请求都经 src/api.ts 的封装（带 3s 超时 + AbortController）。
 *
 * ★ 连接语义（三态，如实呈现，不伪造）：
 *   - 'loading'：首次请求进行中；
 *   - 'online' ：两个接口都成功 ⇒ 有真实数据；
 *   - 'offline'：任一接口失败/超时 ⇒ 视为"后端未连接"，清空数据（绝不显示假的 0/假模块）。
 *
 * 未捕获 rejection 的处理：refresh() 内部 try/catch 全部包住，永不抛出；
 * 组件里用 `void refresh()` 调用即可。
 *
 * StrictMode/卸载：用自增序号 seq 作废旧请求结果，避免"已卸载还 setState"与竞态。
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import {
  getSelfCheck,
  listModules,
  type ModuleView,
  type SelfCheckReport,
} from '../api'

/** 连接状态。 */
export type ConnectionState = 'loading' | 'online' | 'offline'

/** useAppStatus 返回值。 */
export interface AppStatus {
  state: ConnectionState
  /** 仅 online 时有效；offline/loading 时为空数组。 */
  modules: ModuleView[]
  /** 仅 online 时非空。 */
  selfcheck: SelfCheckReport | null
  /** offline 时的错误摘要（顶栏/状态栏 tooltip 用）。 */
  error: string
  /** 上次成功读取后端的时刻（ms epoch）；未成功为 null。 */
  lastUpdated: number | null
  /** 是否有请求在飞（刷新按钮 disabled 用）。 */
  refreshing: boolean
  /** 手动刷新。 */
  refresh: () => void
}

/** 真读后端状态：请求 + 错误处理 + 3s 超时 + 手动刷新。 */
export function useAppStatus(): AppStatus {
  const [state, setState] = useState<ConnectionState>('loading')
  const [modules, setModules] = useState<ModuleView[]>([])
  const [selfcheck, setSelfcheck] = useState<SelfCheckReport | null>(null)
  const [error, setError] = useState('')
  const [lastUpdated, setLastUpdated] = useState<number | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const seqRef = useRef(0)

  const refresh = useCallback(async () => {
    const seq = ++seqRef.current
    setRefreshing(true)
    try {
      // 两个接口并发；任一失败即整体判为未连接（Promise.all 快速失败）。
      const [mods, report] = await Promise.all([listModules(3000), getSelfCheck(3000)])
      if (seq !== seqRef.current) return // 已被更新的请求/卸载作废
      setModules(mods)
      setSelfcheck(report)
      setState('online')
      setError('')
      setLastUpdated(Date.now())
    } catch (e) {
      if (seq !== seqRef.current) return
      setModules([])
      setSelfcheck(null)
      setState('offline')
      setError(e instanceof Error ? e.message : String(e))
      setLastUpdated(null)
    } finally {
      if (seq === seqRef.current) setRefreshing(false)
    }
  }, [])

  useEffect(() => {
    void refresh()
    // 卸载（含 StrictMode 的重跑）时递增序号，令在途请求结果失效。
    return () => {
      seqRef.current++
    }
  }, [refresh])

  return { state, modules, selfcheck, error, lastUpdated, refreshing, refresh }
}
