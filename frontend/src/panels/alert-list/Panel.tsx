import { useCallback, useEffect, useRef, useState } from 'react'
import { fetchAlerts, type AlertRecord } from './api'
import { useWorkbench } from '../../shell/workbench'
import { useEvidenceId } from '../../shell/evidence'

/** 前端列表最多保留的条数（防无限增长）。 */
const MAX_ALERTS = 500

/** 首屏历史条数。 */
const HISTORY_PAGE_SIZE = 50

/** 重连补拉的增量页大小（后端上限 500）。 */
const BACKFILL_PAGE_SIZE = 500

/** 重连退避：1s 起，逐次翻倍，上限 30s。 */
const RECONNECT_BASE_MS = 1000
const RECONNECT_MAX_MS = 30000

/** 连接稳定存活超过该时长才重置退避（避免"连上即断"时疯狂重连）。 */
const STABLE_CONNECTION_MS = 10000

/** WS 消息契约：{"type":"alert","data":{...AlertRecord}} */
interface AlertMessage {
  type?: string
  data?: AlertRecord
}

/**
 * 合并告警：按 id 去重、新到在前、只保留最新 MAX_ALERTS 条。
 *
 * incoming 可以是一条（WS 实时）或一批（历史/补拉），两种都走这里。
 */
function mergeAlerts(prev: AlertRecord[], incoming: AlertRecord[]): AlertRecord[] {
  if (incoming.length === 0) return prev
  const seen = new Set<number>()
  const merged: AlertRecord[] = []
  const sorted = [...incoming].sort((a, b) => b.id - a.id)
  for (const a of sorted.concat(prev)) {
    if (seen.has(a.id)) continue
    seen.add(a.id)
    merged.push(a)
    if (merged.length >= MAX_ALERTS) break
  }
  return merged
}

/** 严重度 → 颜色令牌工具类（var(--danger)/var(--warn)/var(--ok)，不硬编码颜色）。 */
function severityClass(severity: string): string {
  switch (severity.trim().toLowerCase()) {
    case 'critical':
    case 'high':
      return 'text-danger'
    case 'medium':
    case 'warn':
    case 'warning':
      return 'text-warn'
    case 'low':
    case 'info':
      return 'text-ok'
    default:
      return 'text-dim'
  }
}

/** HH:MM:SS（本地时区）；无法解析时回退原串，绝不显示 "null"。 */
function fmtClock(iso: string): string {
  if (!iso) return '-'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const p2 = (n: number) => String(n).padStart(2, '0')
  return `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`
}

/** MM-DD；无法解析时返回空串（调用方不渲染日期段）。 */
function fmtDay(iso: string): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const p2 = (n: number) => String(n).padStart(2, '0')
  return `${p2(d.getMonth() + 1)}-${p2(d.getDate())}`
}

function formatEndpoint(ip: string, port: number): string {
  if (!ip) return '-'
  return port > 0 ? `${ip}:${port}` : ip
}

/**
 * 实时告警面板。
 *
 * 数据流：
 *   1. 首屏 GET /api/alerts 拉历史（归一化后新到在前）；
 *   2. 动态工作台连 ws(s)://<host>/api/ws/alerts 收实时告警（插到顶部，最多 500 条）；
 *   3. 断线指数退避重连，连上后先按 since_id=当前最大 id 补拉增量。
 *
 * ★ 静态工作台（16-6）：一次分析一个证据包。拉告警带 `capture_id=<当前证据包>`，
 *   未选证据包时不请求、不连 WS，直接显示"请先选择证据包"；
 *   若收到 WS 推送，只接受 `capture_id` 与当前证据包一致的告警（避免切换文件串味）。
 */
export function AlertListPanel() {
  // 当前工作台决定查询归属与是否连 WS：静态工作台是一次性分析，不需要实时推送。
  const wb = useWorkbench()
  const mode = wb === 'static' ? 'static' : 'live'
  const isLive = wb === 'live'
  // 静态工作台：当前证据包（'' = 未选，不请求）。
  const evidenceId = useEvidenceId()
  const isStatic = wb === 'static'
  const needsEvidence = isStatic && evidenceId === ''

  const [alerts, setAlerts] = useState<AlertRecord[]>([])
  const [connected, setConnected] = useState(false)
  const [error, setError] = useState('')

  const maxIDRef = useRef(0)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimerRef = useRef<number | null>(null)
  const backoffRef = useRef(RECONNECT_BASE_MS)
  const openedAtRef = useRef(0)

  // 合并一批告警并推进最大 id（补拉用）。
  const applyIncoming = useCallback((items: AlertRecord[]) => {
    if (items.length === 0) return
    for (const a of items) {
      if (typeof a.id === 'number' && a.id > maxIDRef.current) {
        maxIDRef.current = a.id
      }
    }
    setAlerts((prev) => mergeAlerts(prev, items))
  }, [])

  useEffect(() => {
    // ★ 静态工作台未选证据包：不请求、不连 WS，清空旧文件告警。
    if (needsEvidence) {
      setAlerts([])
      setConnected(false)
      setError('')
      return
    }

    let cancelled = false

    // 切换证据包（或工作台）时清空旧列表与增量游标，避免旧文件告警串味。
    maxIDRef.current = 0
    setAlerts([])

    // 静态工作台按当前证据包过滤；动态工作台不带 capture_id（行为不变）。
    const captureId = isStatic ? evidenceId : undefined

    // 连上（含重连）后补拉 since_id 增量：填平"历史已拉、WS 尚未订阅"的缺口。
    const backfill = async () => {
      try {
        const page = await fetchAlerts(1, BACKFILL_PAGE_SIZE, maxIDRef.current, mode, captureId)
        if (!cancelled) applyIncoming(page.items)
      } catch {
        // 补拉失败不致命：下一次重连会再试。
      }
    }

    const scheduleReconnect = () => {
      if (cancelled) return
      if (reconnectTimerRef.current !== null) return
      const delay = backoffRef.current
      backoffRef.current = Math.min(backoffRef.current * 2, RECONNECT_MAX_MS)
      reconnectTimerRef.current = window.setTimeout(() => {
        reconnectTimerRef.current = null
        connect()
      }, delay)
    }

    const connect = () => {
      // 静态工作台不连 WS（一次性分析，没有实时推送）。
      if (cancelled || !isLive) return
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
      const url = `${proto}://${window.location.host}/api/ws/alerts`

      let ws: WebSocket
      try {
        ws = new WebSocket(url)
      } catch {
        scheduleReconnect()
        return
      }
      wsRef.current = ws

      ws.onopen = () => {
        if (cancelled) {
          ws.close()
          return
        }
        openedAtRef.current = Date.now()
        setConnected(true)
        setError('')
        void backfill()
      }

      ws.onmessage = (ev) => {
        if (cancelled) return
        try {
          const msg = JSON.parse(ev.data) as AlertMessage
          if (msg && msg.type === 'alert' && msg.data && typeof msg.data.id === 'number') {
            // ★ 静态工作台只接收当前证据包的告警，否则切换文件后旧文件的告警会串进来。
            if (isStatic && msg.data.capture_id !== evidenceId) return
            applyIncoming([msg.data])
          }
        } catch {
          // 非 JSON / 未知消息：忽略，不影响后续。
        }
      }

      ws.onclose = () => {
        if (cancelled) return
        if (wsRef.current === ws) wsRef.current = null
        setConnected(false)
        // 只有"稳定存活过一段时间"的连接断开才重置退避；连上即断则继续翻倍。
        const lasted = openedAtRef.current > 0 ? Date.now() - openedAtRef.current : 0
        openedAtRef.current = 0
        if (lasted >= STABLE_CONNECTION_MS) {
          backoffRef.current = RECONNECT_BASE_MS
        }
        scheduleReconnect()
      }

      ws.onerror = () => {
        // 浏览器随后一定会触发 onclose；这里只确保连接被关闭。
        try {
          ws.close()
        } catch {
          // ignore
        }
      }
    }

    // 首次加载：先拉历史，再连 WS（连上后还会按 since_id 补一次增量）。
    ;(async () => {
      try {
        const page = await fetchAlerts(1, HISTORY_PAGE_SIZE, 0, mode, captureId)
        if (!cancelled) applyIncoming(page.items)
      } catch (e) {
        if (!cancelled) setError(String(e))
      } finally {
        // 只有动态工作台才连 WS；静态工作台只做一次性拉取。
        if (!cancelled && isLive) connect()
      }
    })()

    return () => {
      cancelled = true
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current)
        reconnectTimerRef.current = null
      }
      const ws = wsRef.current
      wsRef.current = null
      if (ws) {
        try {
          ws.close()
        } catch {
          // ignore
        }
      }
    }
  }, [applyIncoming, mode, isLive, isStatic, evidenceId, needsEvidence])

  const total = alerts.length

  return (
    <div className="flex h-full min-h-0 flex-col gap-2">
      <div className="flex shrink-0 flex-wrap items-baseline gap-3">
        <h2 className="text-lg font-semibold">{wb === 'live' ? '实时告警' : '告警'}</h2>
        {isLive && (
          <span className={connected ? 'text-ok' : 'text-warn'} title={connected ? 'WebSocket 已连接' : 'WebSocket 重连中'}>
            {connected ? '● 已连接' : '○ 重连中'}
          </span>
        )}
        <span className="text-sm text-dim">共 {total} 条</span>
        <button
          className="rounded-sm border border-subtle px-2.5 py-1 text-sm text-fg hover:bg-elevated disabled:cursor-not-allowed disabled:opacity-50"
          onClick={() => setAlerts([])}
          disabled={total === 0}
        >
          清空视图
        </button>
      </div>

      {error && <div className="sev-danger shrink-0">{error}</div>}

      {needsEvidence ? (
        <div className="flex flex-1 items-center justify-center panel-surface text-dim">
          请先选择证据包
        </div>
      ) : (
        <div className="flex-1 overflow-auto min-h-0 panel-surface">
          <table>
            <thead>
              <tr>
                <th>时间</th>
                <th>严重度</th>
                <th>规则ID</th>
                <th>规则名</th>
                <th>源 → 目的</th>
                <th>缓冲+偏移</th>
                <th>片段</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-dim">
                    暂无告警
                  </td>
                </tr>
              ) : (
                alerts.map((a) => (
                  <tr key={a.id}>
                    <td className="mono tabular-nums whitespace-nowrap" title={a.time}>
                      {a.time ? `${fmtDay(a.time)} ${fmtClock(a.time)}` : '-'}
                    </td>
                    <td className={`whitespace-nowrap ${severityClass(a.severity)}`}>
                      {a.severity || '-'}
                    </td>
                    <td className="mono whitespace-nowrap">{a.rule_id || '-'}</td>
                    <td className="whitespace-normal">{a.name || '-'}</td>
                    <td className="mono whitespace-nowrap">
                      {formatEndpoint(a.src_ip, a.src_port)} → {formatEndpoint(a.dst_ip, a.dst_port)}
                    </td>
                    <td className="mono whitespace-nowrap">
                      {a.buffer || '-'}
                      {typeof a.offset === 'number' ? `+${a.offset}` : ''}
                    </td>
                    <td className="mono">
                      <span className="block truncate" style={{ maxWidth: '30rem' }} title={a.snippet}>
                        {a.snippet || '-'}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
