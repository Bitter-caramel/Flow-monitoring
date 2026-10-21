/**
 * 工作台级「当前证据包」上下文。
 *
 * ★ 静态分析是"一次分析一个证据包"：告警、包列表、分析任务都要跟随同一个
 *   当前证据包。选中值存进 `location.search` 的 `capture` 参数
 *   （如 `?capture=de12a5db...#/static/panels.alert-list`），URL 是唯一数据源。
 *
 * 约束（任务 16-6）：
 *   - 只改 search，不动 hash：一律 `history.replaceState`，不刷新、不新增历史记录；
 *   - 没有 `capture` 参数时默认选 imported_at 最新的一项，并写回 URL；
 *   - 没有任何抓包文件时由上下文栏显示空态，静态面板自行显示"请先选择证据包"。
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react'
import type { ReactNode } from 'react'
import { listCaptures, type CaptureRecord } from '../api'

/** URL search 里的证据包参数名。 */
export const EVIDENCE_PARAM = 'capture'

/** 下拉里一次取的文件数（后端 limit 上限之外由后端兜底；这里足够覆盖日常复盘）。 */
const CAPTURE_PAGE_SIZE = 50

/** 从当前 URL 读取证据包 id（缺省返回 ''）。 */
function readEvidenceParam(): string {
  if (typeof window === 'undefined') return ''
  return new URLSearchParams(window.location.search).get(EVIDENCE_PARAM) ?? ''
}

/**
 * 把证据包 id 写回 URL 的 search。
 *
 * ★ 只用 replaceState：不刷新页面、不新增历史记录；
 *   显式拼上 pathname/search/hash，保证 hash 路由原样保留。
 */
function writeEvidenceParam(id: string): void {
  if (typeof window === 'undefined') return
  const url = new URL(window.location.href)
  if (id) {
    url.searchParams.set(EVIDENCE_PARAM, id)
  } else {
    url.searchParams.delete(EVIDENCE_PARAM)
  }
  window.history.replaceState(
    window.history.state,
    '',
    `${url.pathname}${url.search}${url.hash}`,
  )
}

/** imported_at 解析：缺失/非法返回 null（调用方退化到列表第一项）。 */
function parseImportedAt(value: string | undefined): number | null {
  if (!value) return null
  const t = Date.parse(value)
  return Number.isFinite(t) ? t : null
}

/**
 * 选 imported_at 最新的一项。
 *
 * ★ imported_at 缺失/相等/全部非法时退化到列表第一项（后端已按导入时间倒序），
 *   绝不因为脏数据抛异常。
 */
function pickLatestCapture(items: CaptureRecord[]): CaptureRecord | null {
  if (items.length === 0) return null
  let best = items[0]
  let bestTime = parseImportedAt(best.imported_at)
  for (const item of items.slice(1)) {
    const t = parseImportedAt(item.imported_at)
    if (t === null) continue
    if (bestTime === null || t > bestTime) {
      best = item
      bestTime = t
    }
  }
  return best
}

/** useEvidence 的返回值（工作台级状态 + 操作）。 */
export interface EvidenceState {
  /** 当前证据包 id；'' 表示未选。 */
  id: string
  /** 当前证据包记录（列表里找不到时为 null）。 */
  capture: CaptureRecord | null
  /** 已导入的抓包文件（下拉数据源）。 */
  captures: CaptureRecord[]
  /** 文件总数（后端 total）。 */
  total: number
  /** 是否正在拉取文件列表。 */
  loading: boolean
  /** 拉取失败文案（成功时为空）。 */
  error: string
  /** 切换当前证据包（写 replaceState，不新增历史）。 */
  select: (id: string) => void
}

/**
 * 工作台级证据包状态。
 *
 * enabled=false（非静态工作台）时不拉列表、不做默认选择，避免动态工作台
 * 平白往 URL 里塞 capture 参数；切到静态工作台后自动生效。
 */
export function useEvidence(enabled: boolean): EvidenceState {
  const [id, setId] = useState(() => readEvidenceParam())
  const [captures, setCaptures] = useState<CaptureRecord[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // 浏览器前进/后退可能换到另一条带不同 search 的历史记录：
  // 以 URL 为准重新同步（replaceState 不会触发本监听）。
  useEffect(() => {
    function onPopState() {
      setId(readEvidenceParam())
    }
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  useEffect(() => {
    if (!enabled) return
    let cancelled = false
    setLoading(true)
    listCaptures(0, CAPTURE_PAGE_SIZE)
      .then((res) => {
        if (cancelled) return
        setCaptures(res.items)
        setTotal(res.total)
        setError('')
        setLoading(false)
        // 已有 capture 参数就尊重用户选择（即使它不在前 50 条里）；
        // 没有才默认选最近导入的一个，并 replaceState 写回 URL。
        if (!readEvidenceParam()) {
          const latest = pickLatestCapture(res.items)
          if (latest) {
            writeEvidenceParam(latest.id)
            setId(latest.id)
          }
        }
      })
      .catch((e) => {
        if (cancelled) return
        setError(e instanceof Error ? e.message : String(e))
        setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [enabled])

  const select = useCallback((next: string) => {
    writeEvidenceParam(next)
    setId(next)
  }, [])

  const capture = useMemo(
    () => captures.find((c) => c.id === id) ?? null,
    [captures, id],
  )

  return { id, capture, captures, total, loading, error, select }
}

/** Context 值：证据包 id + 记录 + 切换函数（供深层面板使用）。 */
interface EvidenceContextValue {
  id: string
  capture: CaptureRecord | null
  select: (id: string) => void
}

const EvidenceContext = createContext<EvidenceContextValue | null>(null)

/**
 * 把当前证据包下发给面板。
 *
 * value 是当前 id（'' 表示未选）；capture 可选，供需要文件元信息的面板使用；
 * onSelect 由 App 注入，分析任务面板点击行时调用。
 */
export function EvidenceProvider({
  value,
  capture = null,
  onSelect,
  children,
}: {
  value: string
  capture?: CaptureRecord | null
  onSelect?: (id: string) => void
  children: ReactNode
}) {
  const select = useCallback(
    (id: string) => {
      onSelect?.(id)
    },
    [onSelect],
  )
  const ctx = useMemo<EvidenceContextValue>(
    () => ({ id: value, capture, select }),
    [value, capture, select],
  )
  return <EvidenceContext.Provider value={ctx}>{children}</EvidenceContext.Provider>
}

/** 当前证据包 id；'' 表示未选。未包在 Provider 内时明确抛错。 */
export function useEvidenceId(): string {
  const ctx = useContext(EvidenceContext)
  if (ctx === null) {
    throw new Error('useEvidenceId 必须在 <EvidenceProvider> 内使用')
  }
  return ctx.id
}

/** 当前证据包记录（列表里找不到时为 null）。未包在 Provider 内时明确抛错。 */
export function useEvidenceCapture(): CaptureRecord | null {
  const ctx = useContext(EvidenceContext)
  if (ctx === null) {
    throw new Error('useEvidenceCapture 必须在 <EvidenceProvider> 内使用')
  }
  return ctx.capture
}

/** 切换当前证据包；未包在 Provider 内时明确抛错。 */
export function useEvidenceSelect(): (id: string) => void {
  const ctx = useContext(EvidenceContext)
  if (ctx === null) {
    throw new Error('useEvidenceSelect 必须在 <EvidenceProvider> 内使用')
  }
  return ctx.select
}

/**
 * 静态工作台顶部的上下文栏：当前证据包下拉 + 文件总数。
 *
 * ★ 无任何 capture 时整条栏只显示"还没有导入任何抓包文件"；静态面板各自显示空态。
 */
export function EvidenceBar({ state }: { state: EvidenceState }) {
  const hasCaptures = state.captures.length > 0
  const selectedMissing =
    state.id !== '' && !state.captures.some((c) => c.id === state.id)

  return (
    <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-subtle bg-panel px-4 py-2">
      <span className="text-sm text-dim">当前证据包：</span>

      {state.error ? (
        <span className="text-sm text-danger">{state.error}</span>
      ) : !hasCaptures ? (
        <span className="text-sm text-dim">
          {state.loading ? '正在加载抓包文件…' : '还没有导入任何抓包文件'}
        </span>
      ) : (
        <select
          value={state.id}
          onChange={(e) => state.select(e.target.value)}
          className="rounded-sm border border-subtle bg-app px-2.5 py-1.5 text-base text-fg"
          aria-label="当前证据包"
        >
          {state.id === '' && <option value="">请选择证据包</option>}
          {selectedMissing && (
            <option value={state.id}>{state.id}（不在当前列表）</option>
          )}
          {state.captures.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}（{c.packet_count} 包）
            </option>
          ))}
        </select>
      )}

      {hasCaptures && (
        <span className="text-sm text-dim">共 {state.total} 个文件</span>
      )}
    </div>
  )
}
