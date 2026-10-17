import { useEffect, useState } from 'react'
import { fetchModulesGraph, type GraphNode, type ModuleGraph } from '../../api'
import { DependencyGraph } from '../../shell/DependencyGraph'

/**
 * 模块拓扑面板。
 *
 * 三态：加载中 / 失败（后端未连接 + 重试）/ 成功（左大框图 + 右小框详情）。
 * 详情只读已取到的 nodes[]，不额外请求任何接口。
 */
export function ModuleGraphPanel() {
  const [graph, setGraph] = useState<ModuleGraph | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selectedId, setSelectedId] = useState('')
  const [reloadKey, setReloadKey] = useState(0)

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

  return (
    <div className="flex h-full min-h-0 gap-3">
      <div className="min-w-0 flex-1 overflow-auto rounded-sm border border-subtle bg-app p-3">
        <DependencyGraph
          nodes={nodes}
          edges={edges}
          selectedId={selectedId}
          onSelect={setSelectedId}
        />
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
          </div>
        )}
      </aside>
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
