/**
 * 模块依赖拓扑图（自研 SVG，无第三方图形库）。
 *
 * ★ 布局是纯函数：同输入必得同输出（无随机、无时钟、无 DOM 测量）。
 * ★ 本轮只做「点节点 → 上层回调 onSelect」，hover 高亮留到后续迭代。
 */
import type { GraphEdge, GraphNode } from '../api'

export interface GraphPoint {
  id: string
  x: number
  y: number
  w: number
  h: number
}

/** 固定节点尺寸与间距（本轮不做自适应测量，确定性优先）。 */
const NODE_W = 180
const NODE_H = 44
const GAP_X = 24
const GAP_Y = 70
const PAD = 16

/** 分层自上而下：L0 最上、L3 最下；未知层排在已知层之后。 */
const LAYER_ORDER = ['L0', 'L1', 'L2', 'L3']

function layerRank(layer: string): number {
  const i = LAYER_ORDER.indexOf(layer)
  return i < 0 ? LAYER_ORDER.length : i
}

/** 按 name 升序（码点比较，避免 locale 差异）；同名再用 id 兜底，保证稳定。 */
function compareNode(a: GraphNode, b: GraphNode): number {
  if (a.name < b.name) return -1
  if (a.name > b.name) return 1
  if (a.id < b.id) return -1
  if (a.id > b.id) return 1
  return 0
}

/**
 * 计算节点坐标：
 *   1. 按 nodes[].layer 分组（层号直接取后端值，前端不重算）；
 *   2. 每层内按 name 升序；
 *   3. 层内第一个节点 x=0，随后逐个 +w+24；每层 y 从 0 开始，逐层 +h+70。
 */
export function layoutModules(nodes: GraphNode[]): GraphPoint[] {
  const byLayer = new Map<string, GraphNode[]>()
  for (const n of nodes) {
    const row = byLayer.get(n.layer)
    if (row) {
      row.push(n)
    } else {
      byLayer.set(n.layer, [n])
    }
  }

  const layers = [...byLayer.keys()].sort((a, b) => {
    const byRank = layerRank(a) - layerRank(b)
    if (byRank !== 0) return byRank
    if (a < b) return -1
    if (a > b) return 1
    return 0
  })

  const out: GraphPoint[] = []
  let y = 0
  for (const layer of layers) {
    const row = (byLayer.get(layer) ?? []).slice().sort(compareNode)
    let x = 0
    for (const n of row) {
      out.push({ id: n.id, x, y, w: NODE_W, h: NODE_H })
      x += NODE_W + GAP_X
    }
    y += NODE_H + GAP_Y
  }
  return out
}

interface StatusStyle {
  symbol: string
  color: string
}

/** 状态双编码（色盲安全）：语义色 + 形状符号。 */
const STATUS: Record<string, StatusStyle> = {
  started: { symbol: '▲', color: 'var(--ok)' },
  stopped: { symbol: '■', color: 'var(--fg-muted)' },
  error: { symbol: '✕', color: 'var(--danger)' },
  unknown: { symbol: '○', color: 'var(--fg-dim)' },
}

function statusOf(state: string): StatusStyle {
  return STATUS[state] ?? STATUS.unknown
}

export interface DependencyGraphProps {
  nodes: GraphNode[]
  edges: GraphEdge[]
  selectedId: string
  onSelect: (id: string) => void
}

export function DependencyGraph({ nodes, edges, selectedId, onSelect }: DependencyGraphProps) {
  const layout = layoutModules(nodes)
  if (layout.length === 0) {
    return <div className="p-4 text-dim">暂无模块数据</div>
  }

  const nodeById = new Map(nodes.map((n) => [n.id, n] as const))
  const pointById = new Map(layout.map((p) => [p.id, p] as const))

  const maxX = layout.reduce((m, p) => Math.max(m, p.x + p.w), 0)
  const maxY = layout.reduce((m, p) => Math.max(m, p.y + p.h), 0)
  const viewW = maxX + PAD * 2
  const viewH = maxY + PAD * 2

  return (
    <svg
      width={viewW}
      height={viewH}
      viewBox={`${-PAD} ${-PAD} ${viewW} ${viewH}`}
      role="img"
      aria-label="模块拓扑图"
      className="block"
    >
      <defs>
        <marker
          id="module-graph-arrow"
          viewBox="0 0 8 8"
          refX="7"
          refY="4"
          markerWidth="8"
          markerHeight="8"
          orient="auto-start-reverse"
        >
          <path d="M0,0 L8,4 L0,8 z" fill="var(--border-strong)" />
        </marker>
      </defs>

      {/* 先画边，再画节点，保证节点覆盖在线之上。 */}
      <g>
        {edges.map((e, i) => {
          const from = pointById.get(e.from)
          const to = pointById.get(e.to)
          if (!from || !to) return null
          // via 以 depends 开头 ⇒ 实线；provides: ⇒ 虚线（如实呈现，不造边）。
          const dashed = !e.via.startsWith('depends')
          return (
            <line
              key={`${e.from}->${e.to}:${e.via}:${i}`}
              x1={from.x + from.w / 2}
              y1={from.y + from.h}
              x2={to.x + to.w / 2}
              y2={to.y}
              stroke="var(--border-strong)"
              strokeWidth={1}
              strokeDasharray={dashed ? '5 4' : undefined}
              markerEnd="url(#module-graph-arrow)"
            />
          )
        })}
      </g>

      <g>
        {layout.map((p) => {
          const n = nodeById.get(p.id)
          if (!n) return null
          const selected = n.id === selectedId
          const st = statusOf(n.state)
          return (
            <g key={n.id} onClick={() => onSelect(n.id)} style={{ cursor: 'pointer' }}>
              <title>{`${n.name} ${n.version}`}</title>
              <rect
                x={p.x}
                y={p.y}
                width={p.w}
                height={p.h}
                rx={4}
                fill="var(--bg-elevated)"
                stroke={selected ? 'var(--accent)' : 'var(--border-subtle)'}
                strokeWidth={selected ? 2 : 1}
              />
              <text x={p.x + 10} y={p.y + 17} fill="var(--fg)" fontSize={12} fontWeight={600}>
                {n.name}
              </text>
              <text x={p.x + 10} y={p.y + 32} fill="var(--fg-dim)" fontSize={9} className="mono">
                {n.version}
              </text>
              {/* 状态双编码：色块 + 符号 */}
              <rect x={p.x + p.w - 44} y={p.y + 10} width={7} height={7} rx={1} fill={st.color} />
              <text x={p.x + p.w - 10} y={p.y + 18} fill={st.color} fontSize={11} textAnchor="end">
                {st.symbol}
              </text>
              {n.core && (
                <text
                  x={p.x + p.w - 10}
                  y={p.y + 33}
                  fill="var(--accent)"
                  fontSize={8}
                  textAnchor="end"
                  className="mono"
                >
                  CORE
                </text>
              )}
            </g>
          )
        })}
      </g>
    </svg>
  )
}
