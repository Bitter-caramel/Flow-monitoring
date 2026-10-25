/**
 * 态势面板：按源 IP 聚合的攻击态势。
 *
 * 数据：GET /api/situation（situation 模块，经宿主网关反代）。
 * ★ 5 秒轮询：它是持续聚合的视图，不需要 WS 推送。
 * ★ 轮询失败**保留上次数据**并显示错误条 —— 不要因为一次抖动就把表格清空。
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { EmptyState, ErrorView, LoadingState } from '../../ui/AsyncState'
import { StatusPill } from '../../ui/StatusPill'
import { formatNumber, formatTime } from '../../ui/format'

const POLL_MS = 5000

interface SituationItem {
  src_ip: string
  level: string
  score: number
  hits: number
  rules: number
  top_rules?: string[]
  first_seen?: string
  last_seen?: string
}

interface SituationResponse {
  items?: SituationItem[]
  total?: number
}

/** 等级 → StatusPill 的 kind。 */
function kindOf(level: string): 'ok' | 'warn' | 'danger' | 'info' | 'dim' {
  switch (level) {
    case 'high':
      return 'danger'
    case 'medium':
      return 'warn'
    case 'low':
      return 'info'
    default:
      return 'dim'
  }
}

/** 等级 → 中文标签。 */
function labelOf(level: string): string {
  switch (level) {
    case 'high':
      return '高危'
    case 'medium':
      return '中危'
    case 'low':
      return '低危'
    default:
      return level || '—'
  }
}

/** 归一化：items 必须是数组（后端给 null 也不能崩）。 */
function normalize(raw: SituationResponse | null | undefined): SituationItem[] {
  const items = raw?.items
  return Array.isArray(items) ? items : []
}

export function SituationPanel() {
  const [items, setItems] = useState<SituationItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>('')
  // 用序号丢弃过期响应（快速轮询时避免旧数据覆盖新数据）
  const seqRef = useRef(0)

  const load = useCallback(async () => {
    const seq = ++seqRef.current
    try {
      const resp = await fetch('/api/situation', { headers: { Accept: 'application/json' } })
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`)
      }
      const data = (await resp.json()) as SituationResponse
      if (seq !== seqRef.current) return // 过期响应，丢弃
      setItems(normalize(data))
      setError('')
    } catch (e) {
      if (seq !== seqRef.current) return
      // ★ 保留上次数据，只显示错误条
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      if (seq === seqRef.current) setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const timer = window.setInterval(load, POLL_MS)
    return () => window.clearInterval(timer) // ★ 卸载必须清理，否则泄漏
  }, [load])

  if (loading && items.length === 0) {
    return <LoadingState label="加载态势数据…" />
  }
  // 无数据且无错误 ⇒ 空态；有错误但无数据 ⇒ 错误态
  if (items.length === 0) {
    if (error) return <ErrorView error={error} onRetry={load} />
    return <EmptyState>暂无态势（还没有命中规则的流量）</EmptyState>
  }

  const topLevel = items[0]?.level ?? ''
  return (
    <div className="flex h-full flex-col gap-3">
      <div className="flex items-center gap-3 text-sm">
        <span className="text-fg">共 {items.length} 个受攻击 IP</span>
        {topLevel && <StatusPill kind={kindOf(topLevel)} label={`最高：${labelOf(topLevel)}`} />}
        <span className="ml-auto text-dim">每 {POLL_MS / 1000} 秒刷新</span>
      </div>

      {error && (
        <div className="rounded-sm border border-subtle bg-elevated px-2 py-1 text-sm text-warn">
          刷新失败：{error}（显示的是上次数据）
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full border-collapse text-sm">
          <thead className="sticky top-0 bg-panel text-left text-dim">
            <tr className="border-b border-subtle">
              <th className="px-2 py-1.5 font-normal">源 IP</th>
              <th className="px-2 py-1.5 font-normal">等级</th>
              <th className="px-2 py-1.5 text-right font-normal">评分</th>
              <th className="px-2 py-1.5 text-right font-normal">命中次数</th>
              <th className="px-2 py-1.5 text-right font-normal">规则种类</th>
              <th className="px-2 py-1.5 font-normal">最后命中</th>
              <th className="px-2 py-1.5 font-normal">主要规则</th>
            </tr>
          </thead>
          <tbody>
            {items.map((it) => {
              const rules = it.top_rules ?? []
              const shown = rules.slice(0, 3).join(', ')
              const more = rules.length > 3 ? ` +${rules.length - 3}` : ''
              return (
                <tr key={it.src_ip} className="border-b border-subtle/60 hover:bg-elevated">
                  <td className="mono px-2 py-1.5 text-fg">{it.src_ip}</td>
                  <td className="px-2 py-1.5">
                    <StatusPill kind={kindOf(it.level)} label={labelOf(it.level)} />
                  </td>
                  {/* ★ 评分不封顶，用千分位显示 */}
                  <td className="px-2 py-1.5 text-right text-fg">{formatNumber(it.score)}</td>
                  <td className="px-2 py-1.5 text-right text-fg">{formatNumber(it.hits)}</td>
                  <td className="px-2 py-1.5 text-right text-dim">{it.rules}</td>
                  <td className="px-2 py-1.5 text-dim">{it.last_seen ? formatTime(it.last_seen) : '—'}</td>
                  <td className="px-2 py-1.5 text-dim" title={rules.join(', ')}>
                    {shown || '—'}
                    {more}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
