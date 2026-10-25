import { useEffect, useState } from 'react'
import { listPackets, type PacketRecord } from '../../api'
import { useEvidenceCapture, useEvidenceId } from '../../shell/evidence'
import { PacketDetail, type PacketRef } from '../../shell/PacketDetail'
import { EmptyState, ErrorView, LoadingState } from '../../ui/AsyncState'
import { Pagination } from '../../ui/Pagination'

// 行内只显示 HH:MM:SS（本地时区，主信息），毫秒用淡色后缀单独渲染，
// 避免每天/每条都重复年月日；完整 ISO 仍放在单元格 title 里（悬停可看）。
function fmtClock(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '-'
  const p2 = (n: number) => String(n).padStart(2, '0')
  return `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`
}

function fmtMillis(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  return `.${String(d.getMilliseconds()).padStart(3, '0')}`
}

// MM-DD（用于列头动态日期与 capture 时间范围）。
function fmtDay(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const p2 = (n: number) => String(n).padStart(2, '0')
  return `${p2(d.getMonth() + 1)}-${p2(d.getDate())}`
}

// capture 时间范围：同一天只写一次日期；跨天两端都写 MM-DD HH:MM:SS。
// 任一字段缺失/不可解析 ⇒ 返回 ''（调用方不渲染这一段，不显示占位符）。
function fmtRange(first?: string, last?: string): string {
  if (!first || !last) return ''
  const firstDay = fmtDay(first)
  const lastDay = fmtDay(last)
  if (!firstDay || !lastDay) return ''
  const firstClock = fmtClock(first)
  const lastClock = fmtClock(last)
  if (firstDay === lastDay) return `${firstDay} ${firstClock} ~ ${lastClock}`
  return `${firstDay} ${firstClock} ~ ${lastDay} ${lastClock}`
}

/**
 * 包列表面板。
 *
 * 功能：
 *   1. 跟随工作台级「当前证据包」（不再自带 capture 选择器）
 *   2. 分页展示包列表（No/时间/源→目的/协议/长度/INFO）
 *
 * 实质功能：真实调 query-api 分页取包，不做假数据。
 * 布局：面板撑满工作区（h-full），仅表格区内部滚动，分页条 sticky 常驻底部。
 * ★ 未选证据包 ⇒ 显示"请先选择证据包"，不请求包列表。
 */
export function PacketListPanel() {
  // 当前证据包来自工作台上下文（App 的上下文栏负责切换）。
  const captureId = useEvidenceId()
  const currentCapture = useEvidenceCapture()

  const [packets, setPackets] = useState<PacketRecord[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [pageSize, setPageSize] = useState(50)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  // 当前点开的包（抽屉数据源）；null = 抽屉关闭。
  const [selected, setSelected] = useState<PacketRef | null>(null)

  // 切换证据包时回到第一页（旧 offset 对新文件没有意义），并关闭抽屉。
  useEffect(() => {
    setOffset(0)
    setSelected(null)
  }, [captureId])

  // 加载包列表（页大小变化时 offset 已归零，见 pageSize 的 onChange）
  useEffect(() => {
    if (!captureId) {
      setPackets([])
      setTotal(0)
      setLoading(false)
      return
    }
    let cancelled = false
    setLoading(true)
    listPackets(captureId, offset, pageSize)
      .then((res) => {
        if (cancelled) return
        setPackets(res.items)
        setTotal(res.total)
        setError('')
        setLoading(false)
      })
      .catch((e) => {
        if (cancelled) return
        setError(String(e))
        setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [captureId, offset, pageSize])

  const currentPage = Math.floor(offset / pageSize) + 1

  // 当前 capture 的时间范围（后端 first_seen/last_seen；缺失则整段不渲染）。
  const timeRange = currentCapture
    ? fmtRange(currentCapture.first_seen, currentCapture.last_seen)
    : ''

  // 当前页所有包同一天 ⇒ 列头补日期；跨天/无有效时间则只写「时间」。
  const firstPacketDay = packets.length > 0 ? fmtDay(packets[0].time ?? '') : ''
  const sameDay =
    firstPacketDay !== '' && packets.every((p) => fmtDay(p.time ?? '') === firstPacketDay)

  // 没有证据包：静态面板统一空态（不请求、不显示误导性的 0 包）。
  if (!captureId) {
    return (
      <div className="flex h-full min-h-0 flex-col gap-2">
        <div className="flex shrink-0 items-baseline gap-2">
          <h2 className="text-lg font-semibold">包列表</h2>
        </div>
        <div className="flex flex-1 flex-col panel-surface">
          <EmptyState className="flex-1">请先选择证据包</EmptyState>
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-full min-h-0 flex-col gap-2">
      <div className="flex shrink-0 items-baseline gap-2">
        <h2 className="text-lg font-semibold">包列表</h2>
        {currentCapture && (
          <span className="text-sm text-dim">· {currentCapture.name}</span>
        )}
        <span className="text-sm text-dim">共 {total} 包</span>
        {timeRange && (
          <span className="text-sm text-dim">
            · 时间范围 <span className="mono">{timeRange}</span>
          </span>
        )}
      </div>

      {error && <ErrorView error={error} className="shrink-0" />}

      <div className="flex-1 overflow-auto min-h-0 panel-surface">
        <table>
          <thead>
            <tr>
              <th>No.</th>
              <th>时间{sameDay ? ` · ${firstPacketDay}` : ''}</th>
              <th>源</th>
              <th>目的</th>
              <th>协议</th>
              <th>长度</th>
              <th>Info</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={7}>
                  <LoadingState label="加载包列表…" />
                </td>
              </tr>
            ) : packets.length === 0 ? (
              <tr>
                <td colSpan={7}>
                  <EmptyState>无数据</EmptyState>
                </td>
              </tr>
            ) : (
              packets.map((p) => {
                const isSelected = selected?.captureId === captureId && selected.no === p.no
                return (
                  <tr
                    key={p.no}
                    className="cursor-pointer"
                    title="点击查看包详情"
                    onClick={() => setSelected({ captureId, no: p.no })}
                    style={
                      isSelected ? { backgroundColor: 'var(--bg-elevated)' } : undefined
                    }
                  >
                    <td
                      className="mono"
                      style={
                        isSelected
                          ? { boxShadow: 'inset 3px 0 0 var(--accent)' }
                          : undefined
                      }
                    >
                      {p.no}
                    </td>
                    <td className="mono tabular-nums whitespace-nowrap" title={p.time}>
                      {p.time ? (
                        <>
                          {fmtClock(p.time)}
                          <span className="text-dim">{fmtMillis(p.time)}</span>
                        </>
                      ) : (
                        '-'
                      )}
                    </td>
                    <td className="mono">{formatEndpoint(p.src_ip, p.src_port)}</td>
                    <td className="mono">{formatEndpoint(p.dst_ip, p.dst_port)}</td>
                    <td>{p.proto}</td>
                    <td className="mono">{p.cap_len}</td>
                    <td className="mono whitespace-normal">{p.info}</td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      <div className="sticky bottom-0 z-10 flex items-center justify-between gap-2 border-t border-subtle bg-panel px-3 py-2">
        <Pagination
          page={currentPage}
          pageSize={pageSize}
          total={total}
          onChange={(p) => setOffset((p - 1) * pageSize)}
        />

        <label className="flex items-center gap-1 text-sm text-dim">
          每页
          <select
            value={pageSize}
            onChange={(e) => {
              setPageSize(Number(e.target.value))
              setOffset(0)
            }}
            className="rounded-sm border border-subtle bg-app px-2 py-1 text-sm text-fg"
          >
            {[50, 100, 200, 500].map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
          条
        </label>
      </div>

      {selected && (
        <PacketDetail packet={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  )
}

function formatEndpoint(ip: string, port: number): string {
  if (port > 0) return `${ip}:${port}`
  return ip
}
