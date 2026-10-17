import { useEffect, useRef, useState } from 'react'
import {
  fetchModuleImpact,
  fetchModulesGraph,
  postModuleDisable,
  postModuleEnable,
  type CascadeResult,
  type GraphNode,
  type ModuleGraph,
  type ModuleImpact,
} from '../../api'
import { ConfirmDialog } from '../../shell/ConfirmDialog'
import { DependencyGraph } from '../../shell/DependencyGraph'

/** 先取 impact、再弹确认框的待办动作。stop=true 表示“停用”，false 表示“启用”。 */
interface PendingAction {
  node: GraphNode
  impact: ModuleImpact
  stop: boolean
}

/** 内嵌模块的兜底理由：后端 impact.block_reason 取不到时用这句。 */
const INPROCESS_BLOCK_FALLBACK = '内嵌于宿主进程：随宿主运行，没有独立进程可启停'

/**
 * 模块拓扑面板。
 *
 * 三态：加载中 / 失败（后端未连接 + 重试）/ 成功（左大框图 + 右小框详情）。
 * 右侧详情底部提供启停动作：先取 GET /impact 展示影响面，二次确认后才真跑；
 * ★ 不做乐观更新：只有 POST 成功后才重新拉图，失败原文红字展示。
 */
export function ModuleGraphPanel() {
  const [graph, setGraph] = useState<ModuleGraph | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selectedId, setSelectedId] = useState('')
  const [reloadKey, setReloadKey] = useState(0)
  const [resetSignal, setResetSignal] = useState(0)

  // 启停交互状态：pending 非空 = 确认框打开（impact 已取到）。
  const [pending, setPending] = useState<PendingAction | null>(null)
  const [checking, setChecking] = useState(false)
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState('')
  const [result, setResult] = useState<CascadeResult | null>(null)
  // 内嵌模块按钮常禁，但仍要取 impact 拿后端 block_reason（优先展示后端文案）。
  const [inprocessBlockReason, setInprocessBlockReason] = useState('')
  // 防止“先点 A 再点 B”时 A 的 impact 晚到，覆盖 B 的弹窗。
  const actionSeq = useRef(0)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError('')
    fetchModulesGraph()
      .then((data) => {
        if (cancelled) return
        setGraph(data)
        setLoading(false)
      })
      .catch(() => {
        if (cancelled) return
        setGraph(null)
        setError('后端未连接')
        setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [reloadKey])

  // 内嵌模块：按钮常禁，但仍要发 impact 请求拿后端 block_reason（禁用按钮点不动，
  // 不能靠点击触发，故按选中项变化按需拉取）。取不到时后端文案为空，用前端常量兜底。
  const selectedInProcess =
    graph?.nodes.find((n) => n.id === selectedId)?.inprocess === true
  useEffect(() => {
    if (!selectedInProcess) {
      setInprocessBlockReason('')
      return
    }
    let cancelled = false
    fetchModuleImpact(selectedId)
      .then((impact) => {
        if (!cancelled) setInprocessBlockReason(impact.block_reason || '')
      })
      .catch(() => {
        if (!cancelled) setInprocessBlockReason('')
      })
    return () => {
      cancelled = true
    }
  }, [selectedId, selectedInProcess])

  /** 切换选中节点：作废未完成的 impact 请求，并清空上一个动作的结果/错误。 */
  function handleSelect(id: string) {
    actionSeq.current += 1
    setSelectedId(id)
    setPending(null)
    setChecking(false)
    setActionError('')
    setResult(null)
  }

  /**
   * 点“停用/启用”后：先取 impact（不乐观更新），成功才弹确认框。
   * 影响面请求失败时只把后端文案红字展示在详情底部，不弹窗、不发启停请求。
   */
  async function beginAction(node: GraphNode) {
    actionSeq.current += 1
    const seq = actionSeq.current
    const stop = node.enabled
    setChecking(true)
    setActionError('')
    setResult(null)
    try {
      const impact = await fetchModuleImpact(node.id)
      if (seq !== actionSeq.current) return
      setPending({ node, impact, stop })
    } catch (e) {
      if (seq !== actionSeq.current) return
      setActionError(errText(e))
    } finally {
      if (seq === actionSeq.current) setChecking(false)
    }
  }

  /**
   * 确认后真跑 enable/disable。
   *
   * ★ 只有请求成功才 setResult + 重新拉图（失败不刷新、不改本地状态）；
   * ★ 200 但级联里某步失败：仍展示账本，由 ResultSummary 红字标“部分失败”；
   * ★ 409/400 等：后端文案原样进 actionError 红字展示，绝不吞。
   */
  async function confirmAction() {
    if (!pending || busy) return
    // can_disable=false（core / 连带 core）时确认按钮已禁用，这里再兜一层。
    if (pending.stop && !pending.impact.can_disable) return

    const { node, stop } = pending
    setBusy(true)
    setActionError('')
    try {
      const res = stop ? await postModuleDisable(node.id) : await postModuleEnable(node.id)
      setResult(res)
      // ★ 启停成功 ⇒ 广播：shell 重拉 /api/modules 并刷新面板可用性（置灰/恢复入口）。
      window.dispatchEvent(new Event('fm:modules-changed'))
      setPending(null)
      try {
        const next = await fetchModulesGraph()
        setGraph(next) // selectedId 不变 ⇒ 选中节点保持，详情随新 nodes[] 更新。
      } catch (e) {
        setActionError(`启停请求已完成，但刷新拓扑失败：${errText(e)}`)
      }
    } catch (e) {
      setPending(null)
      setActionError(errText(e))
    } finally {
      setBusy(false)
    }
  }

  /** 取消：busy 期间不允许（避免请求还在跑就关掉）。 */
  function cancelAction() {
    if (busy) return
    actionSeq.current += 1
    setPending(null)
    setChecking(false)
  }

  if (loading) {
    return <div className="p-4 text-dim">加载模块拓扑…</div>
  }

  if (error) {
    return (
      <div className="flex flex-col items-start gap-3 p-4">
        <div className="text-danger">{error}</div>
        <button
          className="rounded-sm bg-accent px-3 py-1.5 text-base text-accent-fg hover:opacity-90"
          onClick={() => setReloadKey((k) => k + 1)}
        >
          重试
        </button>
      </div>
    )
  }

  const nodes = graph?.nodes ?? []
  const edges = graph?.edges ?? []
  const selected = nodes.find((n) => n.id === selectedId) ?? null
  // 启用方向且插件目录里没有该模块的二进制：只警告，不禁止确认。
  // 内嵌模块根本不该被启用（按钮已禁用），不显示这条警告。
  const enableWithoutBinary =
    pending !== null &&
    !pending.stop &&
    !pending.node.inprocess &&
    pending.impact.has_binary === false
  // 内嵌模块禁用理由：优先后端 block_reason，取不到用前端常量。
  const inprocessReason = inprocessBlockReason || INPROCESS_BLOCK_FALLBACK

  return (
    <div className="flex h-full min-h-0 gap-3">
      <div className="flex min-w-0 flex-1 flex-col gap-2">
        <div className="flex items-center justify-end">
          <button
            type="button"
            className="rounded-sm border border-subtle bg-elevated px-2 py-1 text-sm text-fg hover:border-strong hover:text-accent"
            onClick={() => setResetSignal((n) => n + 1)}
          >
            重置布局
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-hidden rounded-sm border border-subtle bg-app p-3">
          <DependencyGraph
            nodes={nodes}
            edges={edges}
            selectedId={selectedId}
            onSelect={handleSelect}
            resetSignal={resetSignal}
          />
        </div>
      </div>

      <aside className="w-[320px] min-w-[320px] overflow-auto border-l border-subtle bg-panel p-3">
        {!selected ? (
          <div className="flex h-full items-center justify-center text-dim">点击左侧节点查看详情</div>
        ) : (
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <h2 className="text-base font-semibold">模块详情</h2>
              {selected.core && (
                <span className="rounded-sm bg-accent px-1 py-0.5 text-xs text-accent-fg">CORE</span>
              )}
            </div>
            <NodeDetail node={selected} />
            <ActionArea
              node={selected}
              checking={checking}
              error={actionError}
              result={result}
              inprocessBlockReason={inprocessReason}
              onAction={beginAction}
            />
          </div>
        )}
      </aside>

      <ConfirmDialog
        open={pending !== null}
        title={pending ? `${pending.stop ? '停用' : '启用'} ${pending.node.name}` : ''}
        confirmLabel={pending?.stop ? '确认停用' : enableWithoutBinary ? '仍要启用' : '确认启用'}
        danger={pending?.stop ?? false}
        busy={busy}
        confirmDisabled={pending ? pending.stop && !pending.impact.can_disable : false}
        onConfirm={() => void confirmAction()}
        onCancel={cancelAction}
      >
        {pending && pending.stop && (
          <>
            {pending.impact.dependents.length > 0 ? (
              <p>将先停用这些依赖它的模块：{pending.impact.dependents.join(', ')}</p>
            ) : (
              <p>没有其他模块依赖它</p>
            )}
            {!pending.impact.can_disable && (
              <div className="sev-danger">
                <span className="text-danger">
                  {pending.impact.block_reason || '该模块不可停用'}
                </span>
              </div>
            )}
          </>
        )}
        {pending && !pending.stop && (
          <>
            {pending.impact.has_binary === false && (
              <p className="text-warn">
                该模块没有可执行文件（插件目录里没有它的二进制），启用后无法启动；确认仍要写入 enabled=true 吗？
              </p>
            )}
            <p>将启动该模块（只启动它自己，不级联启动依赖者）。</p>
          </>
        )}
      </ConfirmDialog>
    </div>
  )
}

function NodeDetail({ node }: { node: GraphNode }) {
  const provides = (node.provides ?? []).join('、') || '-'
  const injects = (node.injects ?? []).join('、') || '-'
  return (
    <div className="flex flex-col gap-1.5 text-sm">
      <DetailRow label="名称" value={node.name} />
      <DetailRow label="版本" value={node.version} />
      <DetailRow label="层" value={node.layer} />
      <DetailRow label="core" value={String(node.core)} />
      <DetailRow label="enabled" value={String(node.enabled)} />
      <DetailRow label="state" value={node.state} />
      <DetailRow label="provides" value={provides} />
      <DetailRow label="injects" value={injects} />
      <DetailRow label="http_base" value={node.http_base || '-'} />
      <DetailRow label="binary" value={node.binary || '-'} />
      <DetailRow
        label="可执行文件"
        value={node.inprocess ? '内嵌（随宿主）' : node.has_binary ? '有' : '无'}
      />
      {node.inprocess ? (
        <div className="text-warn text-xs">内嵌于宿主进程：没有独立二进制，也不可单独启停</div>
      ) : !node.has_binary ? (
        <div className="text-warn text-xs">无法启用（需先有 bin/plugins/{node.binary || '<binary>'}）</div>
      ) : null}
    </div>
  )
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-2">
      <span className="w-20 shrink-0 text-dim">{label}</span>
      <span className="mono min-w-0 break-all">{value}</span>
    </div>
  )
}

/** 详情底部动作区：启用/停用按钮 + 影响面请求中的提示 + 错误/结果账本。 */
function ActionArea({
  node,
  checking,
  error,
  result,
  inprocessBlockReason,
  onAction,
}: {
  node: GraphNode
  checking: boolean
  error: string
  result: CascadeResult | null
  inprocessBlockReason: string
  onAction: (node: GraphNode) => void
}) {
  const stop = node.enabled
  // 内嵌模块随宿主进程运行，没有独立进程可启停：启用/停用两个方向都禁用。
  const inprocessBlocked = node.inprocess
  // core 绝不可停：只有“停用”方向需要拦住；若 core 意外处于 disabled，允许启用回来。
  const coreBlocked = node.core && stop
  const buttonDisabled = checking || inprocessBlocked || coreBlocked
  const buttonTitle = inprocessBlocked
    ? inprocessBlockReason || '内嵌模块不可单独启停'
    : coreBlocked
      ? '核心模块不可停用'
      : undefined
  const buttonClass = stop
    ? 'bg-danger text-accent-fg hover:opacity-90'
    : 'bg-accent text-accent-fg hover:opacity-90'

  return (
    <div className="mt-1 flex flex-col gap-2 border-t border-subtle pt-2">
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          disabled={buttonDisabled}
          title={buttonTitle}
          onClick={() => onAction(node)}
          className={`rounded-sm px-3 py-1.5 text-base disabled:cursor-not-allowed disabled:opacity-50 ${buttonClass}`}
        >
          {stop ? '停用' : '启用'}
        </button>
        {checking && <span className="text-sm text-dim">正在获取影响面…</span>}
        {inprocessBlocked && (
          <span className="text-sm text-warn">{inprocessBlockReason || '内嵌模块不可单独启停'}</span>
        )}
        {coreBlocked && <span className="text-sm text-warn">核心模块不可停用</span>}
      </div>

      {/* ★ 失败不吞：后端错误原文红字展示。 */}
      {error && (
        <div className="sev-danger">
          <span className="text-danger">{error}</span>
        </div>
      )}

      {result && <ResultSummary result={result} />}
    </div>
  )
}

/** 一次级联启停的账本摘要：applied / 成功数 / 失败数 / 每步 / restart_hint。 */
function ResultSummary({ result }: { result: CascadeResult }) {
  const steps = result.steps ?? []
  const stopped = result.stopped ?? []
  const failed = result.failed ?? []

  return (
    <div className="flex flex-col gap-1 rounded-sm border border-subtle bg-elevated p-2">
      <div className="text-base font-semibold">操作结果</div>
      <div className="text-sm text-muted">
        {result.enabled ? '启用' : '停用'} {result.id} · applied={String(result.applied)}
        {result.applied ? '（运行期已执行）' : '（仅改清单，需重启生效）'}
      </div>
      <div className="text-sm">
        成功 {stopped.length} 个 / 失败 {failed.length} 个
      </div>

      {/* ★ 有失败：红字“部分失败”并逐条列出 id + 错误原文。 */}
      {failed.length > 0 && (
        <div className="sev-danger">
          <div className="flex flex-col gap-0.5 text-danger">
            <span className="font-semibold">部分失败</span>
            {failed.map((id) => {
              const step = steps.find((s) => s.id === id)
              return (
                <span key={id} className="mono break-all">
                  {id}
                  {step?.err ? `：${step.err}` : ''}
                </span>
              )
            })}
          </div>
        </div>
      )}

      {steps.length > 0 && (
        <div className="flex flex-col gap-0.5">
          {steps.map((s) => (
            <div key={`${s.action}:${s.id}`} className="flex items-baseline gap-2 text-sm">
              <span className="mono min-w-0 break-all">{s.id}</span>
              <span className="shrink-0 text-dim">{s.action}</span>
              {s.ok ? (
                <span className="shrink-0 text-ok">ok</span>
              ) : (
                <span className="min-w-0 break-all text-danger">{s.err || '失败'}</span>
              )}
            </div>
          ))}
        </div>
      )}

      {result.restart_hint && <div className="text-sm text-warn">{result.restart_hint}</div>}
    </div>
  )
}

/** 把 unknown 错误转成可展示文案（后端 Error.message 原样保留）。 */
function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}
