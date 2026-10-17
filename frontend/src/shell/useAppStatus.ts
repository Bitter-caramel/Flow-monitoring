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
  fetchHealth,
  getSelfCheck,
  listModules,
  type HealthStorage,
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
  /** 存储健康（GET /healthz）；拿不到（失败/缺省）时为 null。 */
  storage: HealthStorage | null
  /** 存储健康被读取/检查的时刻（ISO）；未拿到为 undefined。 */
  storageCheckedAt?: string
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
  const [storage, setStorage] = useState<HealthStorage | null>(null)
  const [storageCheckedAt, setStorageCheckedAt] = useState<string | undefined>(undefined)
  const [error, setError] = useState('')
  const [lastUpdated, setLastUpdated] = useState<number | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const seqRef = useRef(0)

  const refresh = useCallback(async () => {
    const seq = ++seqRef.current
    setRefreshing(true)
    try {
      // 三个接口并发（allSettled：任一失败都不影响其它两项，互不阻塞）。
      const [modsRes, reportRes, healthRes] = await Promise.allSettled([
        listModules(3000),
        getSelfCheck(3000),
        fetchHealth(3000),
      ])
      if (seq !== seqRef.current) return // 已被更新的请求/卸载作废

      // 存储是独立项：成功且有 storage ⇒ 展示；失败/缺省 ⇒ null，绝不拖累模块/自检。
      if (healthRes.status === 'fulfilled' && healthRes.value.storage) {
        setStorage(healthRes.value.storage)
        setStorageCheckedAt(healthRes.value.storage.last_check || new Date().toISOString())
      } else {
        setStorage(null)
        setStorageCheckedAt(undefined)
      }

      // 模块/自检仍保持原语义：任一失败即整体判为未连接（快速失败）。
      if (modsRes.status === 'rejected') throw modsRes.reason
      if (reportRes.status === 'rejected') throw reportRes.reason

      setModules(modsRes.value)
      setSelfcheck(reportRes.value)
      setState('online')
      setError('')
      setLastUpdated(new Date().getTime())
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

  // ★ 模块启停成功后由 module-graph 面板广播；复用 refresh 重拉三个接口，
  //   让状态栏与面板可用性（registry.setEnabledModules）立即跟上。
  useEffect(() => {
    const onModulesChanged = () => {
      void refresh()
    }
    window.addEventListener('fm:modules-changed', onModulesChanged)
    return () => {
      window.removeEventListener('fm:modules-changed', onModulesChanged)
    }
  }, [refresh])

  return {
    state,
    modules,
    selfcheck,
    storage,
    storageCheckedAt,
    error,
    lastUpdated,
    refreshing,
    refresh,
  }
}
