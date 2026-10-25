import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ApiError,
  createStaticRun,
  fetchRuns,
  listCaptures,
  type CaptureRecord,
  type RunRecord,
} from '../../api'
import { useEvidenceId, useEvidenceSelect } from '../../shell/evidence'
import { EmptyState, ErrorView, LoadingState } from '../../ui/AsyncState'
import { StatusPill, type StatusKind } from '../../ui/StatusPill'
import { formatBytes, formatDuration } from '../../ui/format'

/** 轮询间隔：仅当存在 running 任务时生效。 */
const POLL_INTERVAL_MS = 2000

/** 并发上限文案（后端 defaultMaxRuns=4，409 时提示）。 */
const TOO_MANY_RUNS_MESSAGE = '并发分析已达上限（4），请等待现有任务结束'

/** captures 为空时的空态文案。 */
const EMPTY_CAPTURES_MESSAGE = '还没有导入任何抓包文件，请先在「抓包导入」上传'

/** 把任意异常转成可展示的文案（优先 Error.message，避免 "Error: " 前缀）。 */
function errText(e: unknown): string {
  if (e instanceof Error && e.message) return e.message
  return String(e)
}

/** 运行状态 → 状态标签（颜色由 StatusPill 的语义令牌决定，不硬编码颜色）。 */
function statusOf(run: RunRecord | undefined): { label: string; kind: StatusKind } {
  if (!run) return { label: '未分析', kind: 'dim' }
  switch (run.state) {
    case 'running':
      return { label: '分析中', kind: 'info' }
    case 'done':
      return { label: '完成', kind: 'ok' }
    case 'error':
      return { label: '失败', kind: 'danger' }
    default:
      return { label: run.state || '-', kind: 'dim' }
  }
}

/** 运行耗时（ms）；running / Go 零值 finished / 非法时间 ⇒ null（耗时未知）。 */
function runDurationMs(run: RunRecord | undefined): number | null {
  if (!run || !run.started || !run.finished) return null
  const start = Date.parse(run.started)
  const end = Date.parse(run.finished)
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return null
  return end - start
}

/** a 是否比 b 更新（started 相同时用 id 兜底，避免不稳定排序）。 */
function isNewerRun(a: RunRecord, b: RunRecord): boolean {
  const ta = Date.parse(a.started)
  const tb = Date.parse(b.started)
  if (Number.isFinite(ta) && Number.isFinite(tb) && ta !== tb) return ta > tb
  return a.id > b.id
}

/**
 * 分析任务面板：一行一个抓包文件（发起分析 / 看状态 / 看告警数）。
 *
 * 数据：captures（文件清单）+ runs（GET /api/capture/runs，只取 mode=static 且有
 * capture_id 的），按 capture_id 分组、每组取 started 最新的一条作为该文件"最近一次分析"。
 *
 * ★ 同一文件分析多次也只显示一行；旧数据（capture_id 为空）直接跳过。
 * ★ 点击某一行（非按钮区域）把该文件设为工作台级「当前证据包」，告警/包列表随之刷新；
 *   行内「分析/重新分析」按钮只发起该文件的 Run，行为不变。
 * ★ 运行中每 2 秒轮询；全部结束或组件卸载时清理定时器。
 */
export function AnalysisRunsPanel() {
  // 工作台级当前证据包：点击行切换；被选中的行有左侧竖条标记。
  const evidenceId = useEvidenceId()
  const selectEvidence = useEvidenceSelect()

  const [captures, setCaptures] = useState<CaptureRecord[]>([])
  const [runs, setRuns] = useState<RunRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [capturesError, setCapturesError] = useState('')
  const [runsError, setRunsError] = useState('')
  const [creatingId, setCreatingId] = useState<string | null>(null)
  const [rowErrors, setRowErrors] = useState<Record<string, string>>({})

  // 请求序号：轮询与"分析成功后刷新"可能并发，只让最新一次响应落地（防竞态）。
  const refreshSeq = useRef(0)

  const loadCaptures = useCallback(async () => {
    try {
      const res = await listCaptures(0, 50)
      setCaptures(res.items)
      setCapturesError('')
    } catch (e) {
      setCapturesError(errText(e))
    }
  }, [])

  const refreshRuns = useCallback(async () => {
    const seq = ++refreshSeq.current
    try {
      const page = await fetchRuns()
      if (seq !== refreshSeq.current) return
      // 只保留静态分析且带 capture_id 的 Run；旧数据缺 capture_id ⇒ 跳过。
      setRuns(page.items.filter((r) => r.mode === 'static' && !!r.capture_id))
      setRunsError('')
    } catch (e) {
      if (seq === refreshSeq.current) setRunsError(errText(e))
    }
  }, [])

  // 首次加载：captures 与 runs 并行拉取；两路都落地后退出加载态。
  useEffect(() => {
    let cancelled = false
    setLoading(true)
    Promise.all([loadCaptures(), refreshRuns()]).finally(() => {
      if (!cancelled) setLoading(false)
    })
    return () => {
      cancelled = true
    }
  }, [loadCaptures, refreshRuns])

  // 按 capture_id 分组，每组取 started 最新的一条（显式取最新，不依赖后端顺序）。
  const latestByCapture = useMemo(() => {
    const map = new Map<string, RunRecord>()
    for (const r of runs) {
      if (r.mode !== 'static' || !r.capture_id) continue
      const prev = map.get(r.capture_id)
      if (!prev || isNewerRun(r, prev)) map.set(r.capture_id, r)
    }
    return map
  }, [runs])

  // ★ 只依赖布尔值：runs 每次轮询都会换新数组，直接依赖会反复重建定时器。
  const hasRunning = runs.some((r) => r.state === 'running')

  // 仅当存在 running 任务时每 2 秒刷新；全部结束或卸载时 clearInterval。
  useEffect(() => {
    if (!hasRunning) return
    const timer = window.setInterval(() => {
      void refreshRuns()
    }, POLL_INTERVAL_MS)
    return () => window.clearInterval(timer)
  }, [hasRunning, refreshRuns])

  async function onAnalyze(captureId: string) {
    // 并发保护：一次只允许一个发起请求在途（按钮同时禁用）。
    if (creatingId !== null) return
    setCreatingId(captureId)
    setRowErrors((prev) => {
      if (!(captureId in prev)) return prev
      const next = { ...prev }
      delete next[captureId]
      return next
    })
    try {
      await createStaticRun(captureId)
      // 成功后刷新列表（新 Run 由 GET /runs 返回，按 capture_id 归到该文件）。
      await refreshRuns()
    } catch (e) {
      // 409 = 并发 Run 已达上限；其余（400/404/…）原样展示后端 error 文案。
      const msg =
        e instanceof ApiError && e.status === 409 ? TOO_MANY_RUNS_MESSAGE : errText(e)
      setRowErrors((prev) => ({ ...prev, [captureId]: msg }))
    } finally {
      setCreatingId(null)
    }
  }

  const loadError = capturesError || runsError

  return (
    <div className="flex flex-col gap-4">
      <section className="flex flex-col gap-2">
        <div className="flex flex-wrap items-baseline gap-2">
          <h2 className="text-lg font-semibold">分析任务</h2>
          <span className="text-sm text-dim">一行一个抓包文件：发起分析、查看状态与告警数</span>
          {hasRunning && (
            <span className="text-sm text-accent">有任务运行中，每 2 秒自动刷新</span>
          )}
        </div>

        {loadError && <ErrorView error={loadError} />}

        <div className="panel-surface overflow-auto">
          <table>
            <thead>
              <tr>
                <th>文件</th>
                <th>包数</th>
                <th>大小</th>
                <th>状态</th>
                <th>告警</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={6}>
                    <LoadingState label="加载分析任务…" />
                  </td>
                </tr>
              ) : captures.length === 0 ? (
                <tr>
                  <td colSpan={6}>
                    <EmptyState>{EMPTY_CAPTURES_MESSAGE}</EmptyState>
                  </td>
                </tr>
              ) : (
                captures.map((c) => {
                  const run = latestByCapture.get(c.id)
                  const status = statusOf(run)
                  const duration = runDurationMs(run)
                  const statusTitle = [
                    status.label,
                    run?.err,
                    duration !== null ? `耗时 ${formatDuration(duration)}` : '',
                  ]
                    .filter(Boolean)
                    .join(' · ')
                  const busy = creatingId === c.id
                  const rowError = rowErrors[c.id]
                  const selected = c.id === evidenceId
                  return (
                    <tr
                      key={c.id}
                      className={`cursor-pointer${selected ? ' bg-elevated' : ''}`}
                      title="点击设为当前证据包"
                      onClick={(e) => {
                        // 按钮区域只发起分析，不顺带切换证据包。
                        if ((e.target as HTMLElement).closest('button')) return
                        selectEvidence(c.id)
                      }}
                    >
                      <td
                        className={`whitespace-normal${selected ? ' border-l-2 border-accent' : ''}`}
                      >
                        {c.name}
                      </td>
                      <td className="tabular-nums">{c.packet_count}</td>
                      <td className="tabular-nums">{formatBytes(c.byte_size)}</td>
                      <td className="whitespace-nowrap" title={statusTitle}>
                        <div className="flex items-center gap-2">
                          <StatusPill kind={status.kind} label={status.label} />
                          {duration !== null && (
                            <span className="tabular-nums text-xs text-dim">
                              {formatDuration(duration)}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="tabular-nums">{run ? run.alerts : '—'}</td>
                      <td>
                        <div className="flex flex-col gap-1">
                          <button
                            type="button"
                            className="rounded-sm border border-subtle px-2.5 py-1 text-sm text-fg hover:bg-elevated disabled:cursor-not-allowed disabled:opacity-50"
                            onClick={() => void onAnalyze(c.id)}
                            disabled={creatingId !== null}
                          >
                            {busy ? '提交中…' : run ? '重新分析' : '分析'}
                          </button>
                          {rowError && <span className="text-sm text-danger">{rowError}</span>}
                        </div>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
