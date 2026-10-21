import { useCallback, useEffect, useRef, useState } from 'react'
import {
  ApiError,
  createStaticRun,
  deleteRun,
  fetchRuns,
  listCaptures,
  type CaptureRecord,
  type RunRecord,
} from '../../api'

/** 轮询间隔：仅当存在 running 任务时生效。 */
const POLL_INTERVAL_MS = 2000

/** 静态工作台的告警面板 hash（点击告警数时跳转）。 */
const ALERT_PANEL_HASH = '#/static/panels.alert-list'

/** 并发上限文案（后端 defaultMaxRuns=4，409 时提示）。 */
const TOO_MANY_RUNS_MESSAGE = '并发分析已达上限（4），请等待现有任务结束'

/** 把任意异常转成可展示的文案（优先 Error.message，避免 "Error: " 前缀）。 */
function errText(e: unknown): string {
  if (e instanceof Error && e.message) return e.message
  return String(e)
}

/** 状态 → 颜色令牌工具类（var(--accent)/var(--ok)/var(--danger)，不硬编码颜色）。 */
function stateClass(state: string): string {
  switch (state) {
    case 'running':
      return 'text-accent'
    case 'done':
      return 'text-ok'
    case 'error':
      return 'text-danger'
    default:
      return 'text-dim'
  }
}

/** 状态 → 中文标签；未知值原样透传（不隐藏后端新状态）。 */
function stateLabel(state: string): string {
  switch (state) {
    case 'running':
      return '运行中'
    case 'done':
      return '完成'
    case 'error':
      return '错误'
    default:
      return state || '-'
  }
}

/**
 * 耗时（finished - started，秒）。
 *
 * 运行中 finished 是 Go 零值时间（远早于 started），此时返回 "—"，
 * 不再编造一个负耗时。
 */
function formatElapsed(run: RunRecord): string {
  const started = Date.parse(run.started)
  const finished = Date.parse(run.finished)
  if (!Number.isFinite(started) || !Number.isFinite(finished)) return '—'
  // 运行中 finished 是 Go 零值时间（远早于 started）；相等则视为 0 耗时。
  if (finished < started) return '—'
  return `${((finished - started) / 1000).toFixed(2)} s`
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

/**
 * 分析任务面板：上方发起静态分析，下方查看 Run 进度。
 *
 * 实质功能（不装样子）：真实调 capture 的 Run 接口；运行中轮询，
 * 全部结束或组件卸载时清理定时器（避免重复请求与内存泄漏）。
 */
export function AnalysisRunsPanel() {
  const [captures, setCaptures] = useState<CaptureRecord[]>([])
  const [runs, setRuns] = useState<RunRecord[]>([])
  const [capturesError, setCapturesError] = useState('')
  const [runsError, setRunsError] = useState('')
  const [createError, setCreateError] = useState('')
  const [creatingId, setCreatingId] = useState<string | null>(null)
  const [stoppingId, setStoppingId] = useState<string | null>(null)

  // 防止轮询重叠：上一次请求未返回时跳过本轮。
  const runsInFlight = useRef(false)

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
    if (runsInFlight.current) return
    runsInFlight.current = true
    try {
      const page = await fetchRuns()
      setRuns(page.items)
      setRunsError('')
    } catch (e) {
      setRunsError(errText(e))
    } finally {
      runsInFlight.current = false
    }
  }, [])

  // 首次加载：captures 与 runs 并行拉取。
  useEffect(() => {
    void loadCaptures()
    void refreshRuns()
  }, [loadCaptures, refreshRuns])

  // ★ 只依赖布尔值：runs 每次轮询都会换新数组，若直接依赖 runs 会反复重建定时器。
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
    // 连点保护：一次只允许一个发起请求在途。
    if (creatingId !== null) return
    setCreatingId(captureId)
    setCreateError('')
    try {
      const run = await createStaticRun(captureId)
      // 立刻插到列表顶部（按 id 去重，避免与轮询结果重复）。
      setRuns((prev) => [run, ...prev.filter((r) => r.id !== run.id)])
    } catch (e) {
      // 409 = 并发 Run 已达上限；其余（400/404/…）原样展示后端 error 文案。
      if (e instanceof ApiError && e.status === 409) {
        setCreateError(TOO_MANY_RUNS_MESSAGE)
      } else {
        setCreateError(errText(e))
      }
    } finally {
      setCreatingId(null)
    }
  }

  async function onStop(id: string) {
    if (stoppingId !== null) return
    setStoppingId(id)
    setRunsError('')
    try {
      const run = await deleteRun(id)
      setRuns((prev) => prev.map((r) => (r.id === run.id ? run : r)))
    } catch (e) {
      setRunsError(errText(e))
    } finally {
      setStoppingId(null)
    }
  }

  function openAlerts() {
    // 切到静态工作台的告警面板（16-3 起静态分析已能产出 static 告警）。
    window.location.hash = ALERT_PANEL_HASH
  }

  return (
    <div className="flex flex-col gap-4">
      <section className="flex flex-col gap-2">
        <div className="flex items-baseline gap-2">
          <h2 className="text-lg font-semibold">分析任务</h2>
          <span className="text-sm text-dim">选择已导入的抓包文件发起静态分析</span>
        </div>

        {createError && <div className="sev-danger">{createError}</div>}
        {capturesError && <div className="sev-danger">{capturesError}</div>}

        <div className="panel-surface overflow-auto">
          <table>
            <thead>
              <tr>
                <th>文件名</th>
                <th>包数</th>
                <th>大小</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {captures.length === 0 ? (
                <tr>
                  <td colSpan={4} className="text-dim">
                    暂无已导入的抓包文件，请先在「抓包导入」中上传
                  </td>
                </tr>
              ) : (
                captures.map((c) => (
                  <tr key={c.id}>
                    <td>{c.name}</td>
                    <td className="tabular-nums">{c.packet_count}</td>
                    <td className="tabular-nums">{formatBytes(c.byte_size)}</td>
                    <td>
                      <button
                        type="button"
                        className="rounded-sm border border-subtle px-2.5 py-1 text-sm text-fg hover:bg-elevated disabled:cursor-not-allowed disabled:opacity-50"
                        onClick={() => void onAnalyze(c.id)}
                        disabled={creatingId !== null}
                      >
                        {creatingId === c.id ? '分析中…' : '分析'}
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="flex flex-col gap-2">
        <div className="flex items-baseline gap-2">
          <h2 className="text-lg font-semibold">任务列表</h2>
          <span className="text-sm text-dim">
            {hasRunning ? '有任务运行中，每 2 秒自动刷新' : `共 ${runs.length} 个任务`}
          </span>
        </div>

        {runsError && <div className="sev-danger">{runsError}</div>}

        <div className="panel-surface overflow-auto">
          <table>
            <thead>
              <tr>
                <th>状态</th>
                <th>来源</th>
                <th>包数</th>
                <th>告警数</th>
                <th>耗时</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {runs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-dim">
                    暂无分析任务，先在上方选择一个抓包文件
                  </td>
                </tr>
              ) : (
                runs.map((r) => (
                  <tr key={r.id}>
                    <td
                      className={`whitespace-nowrap ${stateClass(r.state)}`}
                      title={r.err || r.state}
                    >
                      {stateLabel(r.state)}
                    </td>
                    <td>{r.source || '-'}</td>
                    <td className="tabular-nums">{r.packets}</td>
                    <td className="tabular-nums">
                      {r.alerts > 0 ? (
                        <button
                          type="button"
                          className="text-link underline-offset-2 hover:underline"
                          onClick={openAlerts}
                          title="在告警面板中查看"
                        >
                          {r.alerts}
                        </button>
                      ) : (
                        0
                      )}
                    </td>
                    <td className="whitespace-nowrap tabular-nums">{formatElapsed(r)}</td>
                    <td>
                      {r.state === 'running' ? (
                        <button
                          type="button"
                          className="rounded-sm border border-subtle px-2.5 py-1 text-sm text-fg hover:bg-elevated disabled:cursor-not-allowed disabled:opacity-50"
                          onClick={() => void onStop(r.id)}
                          disabled={stoppingId !== null}
                        >
                          {stoppingId === r.id ? '停止中…' : '停止'}
                        </button>
                      ) : (
                        <span className="text-dim">—</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
