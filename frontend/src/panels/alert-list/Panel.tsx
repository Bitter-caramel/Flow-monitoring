import { Fragment, useCallback, useEffect, useRef, useState } from 'react'
import { fetchAlerts, type AlertRecord } from './api'
import { useWorkbench } from '../../shell/workbench'
import { useEvidenceId } from '../../shell/evidence'
import { PacketDetail, type PacketRef } from '../../shell/PacketDetail'
import { EmptyState, ErrorView, LoadingState } from '../../ui/AsyncState'
import { StatusPill, type StatusKind } from '../../ui/StatusPill'
import { formatTime } from '../../ui/format'

/** 前端最多保留的告警条数（防无限增长；按告警而非事件计数）。 */
const MAX_ALERTS = 500

/** 首屏历史条数（16-10：一页尽量多装事件，减少分页边界把同一包切成两组）。 */
const HISTORY_PAGE_SIZE = 200

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
 * 一个「事件」= 同一个 Run 的同一个包命中的所有告警。
 *
 * ★ 16-10：引擎仍按"一条规则一条告警"返回（`detect.Engine.Match` /
 *   `hotpath.Process` 的语义不变），这里只在展示层按 `(run_id, pkt_no)` 聚合。
 *   后端 `/api/alerts` 的 `total` 仍是**告警条数**，不改成事件数。
 */
interface AlertEvent {
  /** 聚合键：`pkt:<run_id>\u0000<pkt_no>`；pkt_no<=0 的异常数据用 `solo:<id>` 单独成组。 */
  key: string
  /** 命中包号；0 表示没有关联包（不聚合，也不能查看包）。 */
  pktNo: number
  /** 命中该包的告警明细。 */
  alerts: AlertRecord[]
  /** 组内最高严重度（原始严重度字符串）。 */
  severity: string
  /** 事件时间（组内首个告警的时间；同包一般相同）。 */
  time: string
  srcIp: string
  srcPort: number
  dstIp: string
  dstPort: number
  proto: string
  /** 源抓包文件 ID（组内任一告警的 capture_id；同组必然相同）。 */
  captureId: string
}

/** 有效包号：只有 pkt_no > 0 才参与聚合 / 查看包。 */
function alertPktNo(a: AlertRecord): number {
  return typeof a.pkt_no === 'number' && a.pkt_no > 0 ? a.pkt_no : 0
}

/** 聚合键 (run_id, pkt_no)；pkt_no<=0 视为异常数据，按告警 id 各自成组。 */
function eventKeyOf(a: AlertRecord): string {
  const pktNo = alertPktNo(a)
  if (pktNo > 0) return `pkt:${a.run_id ?? ''}\u0000${pktNo}`
  return `solo:${a.id}`
}

/** 严重度权重：越高越严重（critical > high > medium > low > 未知）。 */
function severityRank(severity: string): number {
  switch (severity.trim().toLowerCase()) {
    case 'critical':
      return 4
    case 'high':
      return 3
    case 'medium':
    case 'warn':
    case 'warning':
      return 2
    case 'low':
    case 'info':
      return 1
    default:
      return 0
  }
}

function higherSeverity(a: string, b: string): string {
  return severityRank(b) > severityRank(a) ? b : a
}

function eventFromAlert(a: AlertRecord): AlertEvent {
  return {
    key: eventKeyOf(a),
    pktNo: alertPktNo(a),
    alerts: [a],
    severity: a.severity || '',
    time: a.time || '',
    srcIp: a.src_ip || '',
    srcPort: a.src_port ?? 0,
    dstIp: a.dst_ip || '',
    dstPort: a.dst_port ?? 0,
    proto: a.proto || '',
    captureId: a.capture_id ?? '',
  }
}

/** 展开明细排序：weight 降序；同 weight 按 RuleID 升序。 */
function sortDetails(alerts: AlertRecord[]): AlertRecord[] {
  return [...alerts].sort((a, b) => {
    if (b.weight !== a.weight) return b.weight - a.weight
    return (a.rule_id || '').localeCompare(b.rule_id || '')
  })
}

function countAlerts(events: AlertEvent[]): number {
  let n = 0
  for (const ev of events) n += ev.alerts.length
  return n
}

/** 超过 MAX_ALERTS 时丢弃全局最旧的告警，并清理变空的事件。 */
function capEvents(events: AlertEvent[]): AlertEvent[] {
  let total = countAlerts(events)
  if (total <= MAX_ALERTS) return events

  const capped = events.map((ev) => ({ ...ev, alerts: [...ev.alerts] }))
  while (total > MAX_ALERTS) {
    let minEvent = -1
    let minAlert = -1
    let minID = Number.POSITIVE_INFINITY
    for (let i = 0; i < capped.length; i += 1) {
      const list = capped[i].alerts
      for (let j = 0; j < list.length; j += 1) {
        const id = typeof list[j].id === 'number' ? list[j].id : 0
        if (id < minID) {
          minID = id
          minEvent = i
          minAlert = j
        }
      }
    }
    if (minEvent < 0 || minAlert < 0) break
    capped[minEvent].alerts.splice(minAlert, 1)
    capped[minEvent].severity = capped[minEvent].alerts.reduce(
      (sev, a) => higherSeverity(sev, a.severity || ''),
      '',
    )
    if (capped[minEvent].alerts.length === 0) capped.splice(minEvent, 1)
    total -= 1
  }
  return capped
}

/**
 * 合并一批告警到事件列表（首屏历史 / 重连补拉 / WS 增量共用）。
 *
 * 规则（16-10 D）：
 *   - 先按 id 去重，再按 (run_id, pkt_no) 归组；pkt_no<=0 各自单独成组；
 *   - 并入已有组 ⇒ 只追加明细、严重度可能升级，**行不移动**；
 *   - 新组 ⇒ 插到列表顶部；
 *   - incoming 先按 id 升序处理，保证"最新告警所在的新组"最终排在最前。
 */
function mergeEvents(prev: AlertEvent[], incoming: AlertRecord[]): AlertEvent[] {
  if (incoming.length === 0) return prev

  const seen = new Set<number>()
  for (const ev of prev) {
    for (const a of ev.alerts) {
      if (typeof a.id === 'number') seen.add(a.id)
    }
  }

  const byKey = new Map<string, AlertEvent>()
  const order: string[] = []
  for (const ev of prev) {
    byKey.set(ev.key, ev)
    order.push(ev.key)
  }

  const sorted = [...incoming].sort((a, b) => a.id - b.id)
  for (const a of sorted) {
    if (typeof a.id !== 'number' || seen.has(a.id)) continue
    seen.add(a.id)

    const key = eventKeyOf(a)
    const existing = byKey.get(key)
    if (existing) {
      byKey.set(key, {
        ...existing,
        alerts: [...existing.alerts, a],
        severity: higherSeverity(existing.severity || '', a.severity || ''),
        time: existing.time || a.time || '',
        srcIp: existing.srcIp || a.src_ip || '',
        srcPort: existing.srcPort || a.src_port || 0,
        dstIp: existing.dstIp || a.dst_ip || '',
        dstPort: existing.dstPort || a.dst_port || 0,
        proto: existing.proto || a.proto || '',
        captureId: existing.captureId || a.capture_id || '',
      })
    } else {
      byKey.set(key, eventFromAlert(a))
      order.unshift(key)
    }
  }

  const merged: AlertEvent[] = []
  for (const key of order) {
    const ev = byKey.get(key)
    if (ev) merged.push(ev)
  }
  return capEvents(merged)
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

/** 严重度 → 标签种类（颜色由 StatusPill 的语义令牌决定，不硬编码颜色）。 */
function severityKind(severity: string): StatusKind {
  switch (severity.trim().toLowerCase()) {
    case 'critical':
    case 'high':
      return 'danger'
    case 'medium':
    case 'warn':
    case 'warning':
      return 'warn'
    case 'low':
    case 'info':
      return 'ok'
    default:
      return 'dim'
  }
}

function formatEndpoint(ip: string, port: number): string {
  if (!ip) return '-'
  return port > 0 ? `${ip}:${port}` : ip
}

/**
 * 实时告警面板。
 *
 * 数据流：
 *   1. 首屏 GET /api/alerts 拉历史（归一化后按事件聚合展示）；
 *   2. 动态工作台连 ws(s)://<host>/api/ws/alerts 收实时告警；
 *   3. 断线指数退避重连，连上后先按 since_id=当前最大 id 补拉增量。
 *
 * ★ 16-10 聚合：一个包命中 N 条规则时，界面只显示**一个事件**，展开看明细。
 *   聚合只在前端做，后端 `/api/alerts` 的 `total` 仍是告警条数。
 *
 * ★ 静态工作台（16-6）：一次分析一个证据包。拉告警带 `capture_id=<当前证据包>`，
 *   未选证据包时不请求、不连 WS，直接显示"请先选择证据包"；
 *   若收到 WS 推送，只接受 `capture_id` 与当前证据包一致的告警（避免切换文件串味），
 *   **过滤之后**再做聚合。
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

  const [events, setEvents] = useState<AlertEvent[]>([])
  const [connected, setConnected] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  // 当前点开的告警包（同一个共享抽屉）；null = 关闭。
  const [selected, setSelected] = useState<PacketRef | null>(null)
  // 展开状态以聚合键（run_id+pkt_no）为 key，避免分页刷新后错位。
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set())

  // 切换工作台/证据包时关闭抽屉、清空展开态，避免继续展示上一份数据。
  useEffect(() => {
    setSelected(null)
    setExpanded(new Set())
  }, [wb, evidenceId])

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
    setEvents((prev) => mergeEvents(prev, items))
  }, [])

  const toggleExpanded = useCallback((key: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }, [])

  useEffect(() => {
    // ★ 静态工作台未选证据包：不请求、不连 WS，清空旧文件告警。
    if (needsEvidence) {
      setEvents([])
      setExpanded(new Set())
      setConnected(false)
      setError('')
      setLoading(false)
      return
    }

    let cancelled = false

    // 切换证据包（或工作台）时清空旧列表与增量游标，避免旧文件告警串味。
    maxIDRef.current = 0
    setEvents([])
    setExpanded(new Set())

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
            //   过滤之后再聚合。
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
      setLoading(true)
      try {
        const page = await fetchAlerts(1, HISTORY_PAGE_SIZE, 0, mode, captureId)
        if (!cancelled) applyIncoming(page.items)
      } catch (e) {
        if (!cancelled) setError(String(e))
      } finally {
        if (!cancelled) {
          setLoading(false)
          // 只有动态工作台才连 WS；静态工作台只做一次性拉取。
          if (isLive) connect()
        }
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

  // 两个数字都给：事件数（聚合后）与告警数（后端语义）。
  const totalEvents = events.length
  const totalAlerts = countAlerts(events)

  return (
    <div className="flex h-full min-h-0 flex-col gap-2">
      <div className="flex shrink-0 flex-wrap items-baseline gap-3">
        <h2 className="text-lg font-semibold">{wb === 'live' ? '实时告警' : '告警'}</h2>
        {isLive && (
          <span title={connected ? 'WebSocket 已连接' : 'WebSocket 重连中'}>
            <StatusPill kind={connected ? 'ok' : 'warn'} label={connected ? '已连接' : '重连中'} />
          </span>
        )}
        <span className="text-sm text-dim">
          共 {totalEvents} 个事件（{totalAlerts} 条告警）
        </span>
        <button
          className="rounded-sm border border-subtle px-2.5 py-1 text-sm text-fg hover:bg-elevated disabled:cursor-not-allowed disabled:opacity-50"
          onClick={() => {
            setEvents([])
            setExpanded(new Set())
          }}
          disabled={totalAlerts === 0}
        >
          清空视图
        </button>
      </div>

      {error && <ErrorView error={error} className="shrink-0" />}

      {needsEvidence ? (
        <div className="flex flex-1 flex-col panel-surface">
          <EmptyState className="flex-1">请先选择证据包</EmptyState>
        </div>
      ) : (
        <div className="flex-1 overflow-auto min-h-0 panel-surface">
          <table>
            <thead>
              <tr>
                <th className="w-6" aria-label="展开" />
                <th>时间</th>
                <th>源 → 目的</th>
                <th>协议</th>
                <th>命中规则</th>
                <th>严重度</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {loading && events.length === 0 ? (
                <tr>
                  <td colSpan={7}>
                    <LoadingState label="加载告警…" />
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={7}>
                    <EmptyState>暂无告警</EmptyState>
                  </td>
                </tr>
              ) : (
                events.map((ev) => {
                  // 组内告警的 capture_id / pkt_no 必然相同；取任一即可。
                  const captureId = ev.captureId
                  const pktNo = ev.pktNo
                  // ★ 只在这两个条件同时成立时可用；动态工作台 capture_id 为空 ⇒ 禁用。
                  const canViewPacket = captureId !== '' && pktNo > 0
                  const packetTitle = !captureId
                    ? '实时流量没有归档的包文件'
                    : pktNo > 0
                      ? `查看第 ${pktNo} 个包`
                      : '该告警没有关联包号'
                  const isOpen = expanded.has(ev.key)
                  const hitCount = ev.alerts.length
                  const details = isOpen ? sortDetails(ev.alerts) : []
                  return (
                    <Fragment key={ev.key}>
                      <tr>
                        <td className="w-6">
                          <button
                            type="button"
                            className="rounded-sm px-1 text-sm text-fg hover:bg-elevated"
                            aria-expanded={isOpen}
                            title={isOpen ? '收起命中规则' : `展开命中的 ${hitCount} 条规则`}
                            onClick={() => toggleExpanded(ev.key)}
                          >
                            {isOpen ? '▾' : '▸'}
                          </button>
                        </td>
                        <td className="mono tabular-nums whitespace-nowrap" title={ev.time}>
                          {ev.time ? formatTime(ev.time) : '-'}
                        </td>
                        <td className="mono whitespace-nowrap">
                          {formatEndpoint(ev.srcIp, ev.srcPort)} →{' '}
                          {formatEndpoint(ev.dstIp, ev.dstPort)}
                        </td>
                        <td className="whitespace-nowrap">{ev.proto || '-'}</td>
                        <td className="whitespace-nowrap">命中 {hitCount} 条规则</td>
                        <td className="whitespace-nowrap">
                          <StatusPill kind={severityKind(ev.severity)} label={ev.severity || '-'} />
                        </td>
                        <td>
                          {/* title 放在包一层的 span 上：禁用按钮上部分浏览器不弹 title。 */}
                          <span className="inline-flex" title={packetTitle}>
                            <button
                              type="button"
                              className="rounded-sm border border-subtle px-2 py-0.5 text-sm text-fg hover:bg-elevated disabled:cursor-not-allowed disabled:opacity-50"
                              disabled={!canViewPacket}
                              onClick={() => {
                                if (canViewPacket) setSelected({ captureId, no: pktNo })
                              }}
                            >
                              {canViewPacket ? '查看包' : '—'}
                            </button>
                          </span>
                        </td>
                      </tr>
                      {isOpen && (
                        <tr>
                          <td colSpan={7}>
                            <div className="flex flex-col gap-1">
                              {details.map((a) => {
                                // 明细：严重度 / 规则 ID / 规则名 / 缓冲@偏移（按 weight 降序）。
                                const offsetText =
                                  typeof a.offset === 'number' ? `@${a.offset}` : ''
                                return (
                                  <div
                                    key={a.id}
                                    className="flex flex-wrap items-baseline gap-2 text-sm"
                                  >
                                    <span className={`mono ${severityClass(a.severity)}`}>●</span>
                                    <span className="mono whitespace-nowrap">
                                      {a.rule_id || '-'}
                                    </span>
                                    <span
                                      className={`whitespace-nowrap ${severityClass(a.severity)}`}
                                    >
                                      {a.severity || '-'}
                                    </span>
                                    <span
                                      className="whitespace-normal"
                                      title={a.snippet || ''}
                                    >
                                      {a.name || '-'}
                                    </span>
                                    <span className="mono whitespace-nowrap text-dim">
                                      {(a.buffer || '-') + offsetText}
                                    </span>
                                  </div>
                                )
                              })}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      )}

      {selected && (
        <PacketDetail packet={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  )
}
