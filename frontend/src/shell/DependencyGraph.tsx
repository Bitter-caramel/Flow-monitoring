/**
 * 模块依赖拓扑图（自研 SVG，无第三方图形库）。
 *
 * ★ 布局是纯函数：同输入必得同输出（无随机、无时钟、无 DOM 测量）。
 * ★ 本轮只做「点节点 → 上层回调 onSelect」，hover 高亮留到后续迭代。
 */
import { useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react'
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

/**
 * 沿边的「流向」小箭头：相邻箭头间距（60 ⇒ 视觉更稀疏）、距目标节点的最小留白、
 * 尖端长度与半宽。★ 只按固定间距生成，没有「单边箭头数量上限」。
 */
const ARROW_STEP = 60
const ARROW_END_MARGIN = 16
const ARROW_LEN = 6
const ARROW_HALF = 3

/**
 * 沿 from→to 的直线，算出每个箭头尖端的坐标与角度（纯函数、确定性）。
 * 规则：从起点后 ARROW_STEP 开始，每隔 ARROW_STEP 放一个，
 *       直到距终点 < ARROW_END_MARGIN 为止（无数量上限，长边也能一直有箭头）。
 */
function arrowHeadsFor(
  x1: number,
  y1: number,
  x2: number,
  y2: number,
): { x: number; y: number; deg: number }[] {
  const dx = x2 - x1
  const dy = y2 - y1
  const len = Math.hypot(dx, dy)
  if (!Number.isFinite(len) || len === 0) return []
  const deg = (Math.atan2(dy, dx) * 180) / Math.PI
  const out: { x: number; y: number; deg: number }[] = []
  for (let d = ARROW_STEP; len - d >= ARROW_END_MARGIN; d += ARROW_STEP) {
    const t = d / len
    out.push({ x: x1 + dx * t, y: y1 + dy * t, deg })
  }
  return out
}

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

type PosMap = Record<string, { x: number; y: number }>

interface DragState {
  id: string
  pointerId: number
  startX: number
  startY: number
  originX: number
  originY: number
}

/** 画布平移的拖拽快照：记录按下点与按下时的 pan 原点。 */
interface PanState {
  pointerId: number
  startX: number
  startY: number
  originX: number
  originY: number
}

/** localStorage 键：v1 表示坐标数据结构版本。 */
const STORAGE_KEY = 'fm.graph.pos.v1'

/** 节点 id 集合的稳定指纹（djb2）：纯函数、可复现，不含随机/时钟。 */
function fingerprint(ids: string[]): string {
  const text = ids.slice().sort().join('|')
  let hash = 5381
  for (let i = 0; i < text.length; i++) {
    hash = ((hash << 5) + hash + text.charCodeAt(i)) >>> 0
  }
  return hash.toString(16)
}

/**
 * 坐标只挡非有限数（NaN / ±Infinity），不限制正负。
 * 画布无边界：坐标为任意有限实数，靠 pan 查看。
 */
function normalizeCoord(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null
  return value
}

/** 读取 override；节点集合指纹不符 / 解析失败一律忽略。 */
function loadOverrides(ids: string[]): PosMap {
  const fp = fingerprint(ids)
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return {}
    const stored = JSON.parse(raw) as { fp?: unknown; pos?: unknown }
    if (!stored || stored.fp !== fp) return {}
    if (!stored.pos || typeof stored.pos !== 'object') return {}
    const source = stored.pos as Record<string, unknown>
    const out: PosMap = {}
    for (const id of ids) {
      const rawPoint = source[id]
      if (!rawPoint || typeof rawPoint !== 'object') continue
      const point = rawPoint as { x?: unknown; y?: unknown }
      const x = normalizeCoord(point.x)
      const y = normalizeCoord(point.y)
      if (x === null || y === null) continue
      out[id] = { x, y }
    }
    return out
  } catch {
    return {}
  }
}

/** 只在拖拽结束时写一次，避免每帧写 localStorage。 */
function saveOverrides(ids: string[], pos: PosMap): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ fp: fingerprint(ids), pos }))
  } catch {
    // 隐私模式 / 配额不足：当前会话内的拖拽仍然有效。
  }
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
  /** 父组件点「重置布局」时 +1；变化即丢弃 override 并清掉持久化。 */
  resetSignal?: number
}

export function DependencyGraph({
  nodes,
  edges,
  selectedId,
  onSelect,
  resetSignal,
}: DependencyGraphProps) {
  const ids = nodes.map((n) => n.id)
  const fp = fingerprint(ids)
  const layout = layoutModules(nodes)

  const [pos, setPos] = useState<PosMap>(() => loadOverrides(ids))
  const posRef = useRef<PosMap>(pos)
  const dragRef = useRef<DragState | null>(null)
  const [draggingId, setDraggingId] = useState<string | null>(null)
  // 画布平移：只影响「看的角度」，不写 localStorage，也不改节点坐标。
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 })
  const panRef = useRef<PanState | null>(null)
  const [panning, setPanning] = useState(false)
  const lastResetSignal = useRef<number | undefined>(resetSignal)

  // 节点集合变了 ⇒ 旧坐标不可信，按新指纹重新读取。
  useEffect(() => {
    const next = loadOverrides(ids)
    posRef.current = next
    setPos(next)
  }, [fp])

  // 只在 resetSignal 真正变化时重置（跳过挂载时的那一次，否则会清掉持久化）。
  useEffect(() => {
    if (lastResetSignal.current === resetSignal) return
    lastResetSignal.current = resetSignal
    posRef.current = {}
    setPos({})
    // 「重置布局」同时把画布平移归零（pan 不持久化，只回到正视角）。
    panRef.current = null
    setPan({ x: 0, y: 0 })
    setPanning(false)
    try {
      localStorage.removeItem(STORAGE_KEY)
    } catch {
      // 隐私模式：即使清不掉，本次会话也已回到自动布局。
    }
  }, [resetSignal])

  if (layout.length === 0) {
    return <div className="p-4 text-dim">暂无模块数据</div>
  }

  const nodeById = new Map(nodes.map((n) => [n.id, n] as const))
  // 基准坐标来自确定性分层布局，override 只覆盖被拖动过的节点。
  const pointById = new Map(
    layout.map((p) => {
      const override = pos[p.id]
      if (!override) return [p.id, p] as const
      return [p.id, { ...p, x: override.x, y: override.y }] as const
    }),
  )

  // 画布 = 容器尺寸（svg 用 width/height="100%"、无 viewBox ⇒ 1 用户单位 = 1px，不缩放）；
  // 内容坐标系从 (0,0) 起，靠 pan 平移；箭头按固定间距沿边生成、无数量上限。
  const handleNodePointerDown = (e: ReactPointerEvent<SVGGElement>, id: string) => {
    const point = pointById.get(id)
    if (!point) return
    // 点在节点上时不要触发背景的画布平移（节点拖拽与平移互斥）。
    e.stopPropagation()
    // 点一下就选中：与既有 onClick 行为一致，且拖动开始即可见反馈。
    onSelect(id)
    dragRef.current = {
      id,
      pointerId: e.pointerId,
      startX: e.clientX,
      startY: e.clientY,
      originX: point.x,
      originY: point.y,
    }
    setDraggingId(id)
    try {
      e.currentTarget.setPointerCapture?.(e.pointerId)
    } catch {
      // 老浏览器不支持 capture：仍可在 svg 范围内拖动。
    }
    e.preventDefault()
  }

  const handlePointerMove = (e: ReactPointerEvent<SVGSVGElement>) => {
    const drag = dragRef.current
    if (!drag || drag.pointerId !== e.pointerId) return
    const x = normalizeCoord(drag.originX + (e.clientX - drag.startX)) ?? 0
    const y = normalizeCoord(drag.originY + (e.clientY - drag.startY)) ?? 0
    const next: PosMap = { ...posRef.current, [drag.id]: { x, y } }
    posRef.current = next
    setPos(next)
    e.preventDefault()
  }

  const handlePointerEnd = (e: ReactPointerEvent<SVGSVGElement>) => {
    const drag = dragRef.current
    if (!drag || drag.pointerId !== e.pointerId) return
    dragRef.current = null
    setDraggingId(null)
    // 只在拖拽结束写一次 localStorage。
    saveOverrides(ids, posRef.current)
  }

  // 背景空白处按下：开始平移画布。clientX/clientY 差值累加到 pan 原点上，
  // 因此允许负值（往左上拖），且不做 clamp（大图也能拖到视野里）。
  const handlePanStart = (e: ReactPointerEvent<SVGRectElement>) => {
    // 与节点拖拽互斥：节点 pointerdown 会 stopPropagation，这里只处理真正的空白区。
    if (dragRef.current) return
    panRef.current = {
      pointerId: e.pointerId,
      startX: e.clientX,
      startY: e.clientY,
      originX: pan.x,
      originY: pan.y,
    }
    setPanning(true)
    try {
      e.currentTarget.setPointerCapture?.(e.pointerId)
    } catch {
      // 老浏览器不支持 capture：仍可在背景范围内拖动。
    }
    e.preventDefault()
  }

  const handlePanMove = (e: ReactPointerEvent<SVGRectElement>) => {
    const start = panRef.current
    if (!start || start.pointerId !== e.pointerId) return
    setPan({
      x: start.originX + (e.clientX - start.startX),
      y: start.originY + (e.clientY - start.startY),
    })
    e.preventDefault()
  }

  const handlePanEnd = (e: ReactPointerEvent<SVGRectElement>) => {
    const start = panRef.current
    if (!start || start.pointerId !== e.pointerId) return
    panRef.current = null
    setPanning(false)
  }

  return (
    <svg
      width="100%"
      height="100%"
      role="img"
      aria-label="模块拓扑图"
      className="block h-full w-full select-none"
      style={{ touchAction: 'none' }}
      onPointerMove={handlePointerMove}
      onPointerUp={handlePointerEnd}
      onPointerCancel={handlePointerEnd}
    >
      {/* 铺满整个框的透明 rect：把「框内任意空白处按住平移」的指针事件接住。
          它先绘制（在底层），节点/边绘制在其上，点节点时不会命中它。 */}
      <rect
        x="0"
        y="0"
        width="100%"
        height="100%"
        fill="transparent"
        style={{ cursor: panning ? 'grabbing' : 'grab' }}
        onPointerDown={handlePanStart}
        onPointerMove={handlePanMove}
        onPointerUp={handlePanEnd}
        onPointerCancel={handlePanEnd}
      />

      {/* 整层内容按 pan 平移；节点坐标本身不变（只影响观看角度）。 */}
      <g className="graph-content" transform={`translate(${pan.x}, ${pan.y})`}>
        {/* 先画边，再画节点，保证节点覆盖在线之上。 */}
        <g>
          {edges.map((e, i) => {
            const from = pointById.get(e.from)
            const to = pointById.get(e.to)
            if (!from || !to) return null
            // via 以 depends 开头 ⇒ 实线；provides: ⇒ 虚线（如实呈现，不造边）。
            const dashed = !e.via.startsWith('depends')
            const edgeKey = `${e.from}->${e.to}:${e.via}:${i}`
            const x1 = from.x + from.w / 2
            const y1 = from.y + from.h
            const x2 = to.x + to.w / 2
            const y2 = to.y
            return (
              <g key={edgeKey}>
                <line
                  x1={x1}
                  y1={y1}
                  x2={x2}
                  y2={y2}
                  stroke="var(--border-strong)"
                  strokeWidth={1}
                  strokeDasharray={dashed ? '5 4' : undefined}
                />
                {/* 沿边等距分布的小箭头：尖端朝向 to（依赖者 → 被依赖者）。 */}
                {arrowHeadsFor(x1, y1, x2, y2).map((p, ai) => (
                  <polygon
                    key={`${edgeKey}-arr-${ai}`}
                    transform={`translate(${p.x} ${p.y}) rotate(${p.deg})`}
                    points={`0,0 ${-ARROW_LEN},${ARROW_HALF} ${-ARROW_LEN},${-ARROW_HALF}`}
                    fill="var(--border-strong)"
                  />
                ))}
              </g>
            )
          })}
        </g>

        <g>
          {layout.map((base) => {
            const n = nodeById.get(base.id)
            const p = pointById.get(base.id)
            if (!n || !p) return null
            const selected = n.id === selectedId
            const dragging = draggingId === n.id
            const st = statusOf(n.state)
            return (
              <g
                key={n.id}
                onClick={() => onSelect(n.id)}
                onPointerDown={(e) => handleNodePointerDown(e, n.id)}
                style={{ cursor: dragging ? 'grabbing' : 'grab' }}
              >
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
      </g>
    </svg>
  )
}
