/**
 * 共用的「包详情」抽屉（16-9 升级为 Wireshark 式三栏：协议分层 / 十六进制 / 载荷）。
 *
 * ★ 数据来自 GET /api/v1/captures/{id}/packets/{no}/detail（16-8），一次拿齐三份。
 * ★ 只在传入 packet 且组件挂载/包号变化时请求一次；关闭/切换包时中止在途请求。
 * ★ 命中 packetCache（5 分钟）则完全不发请求。
 * ★ 404 ⇒「该包不存在或文件已被移除」；其它错误展示后端 error 原文。
 */
import { useEffect, useRef, useState, type ReactNode } from 'react'
import {
  ApiError,
  fetchPacketDetail,
  type PacketDetail as PacketDetailData,
  type PacketDetailLayer,
} from '../api'
import { readCachedPacket, writeCachedPacket } from './packetCache'

/** 指向「某个证据包里的第 no 个包」（no 从 1 开始）。 */
export interface PacketRef {
  captureId: string
  no: number
}

type DetailStatus = 'loading' | 'done' | 'missing' | 'error'

/** 完整时间（本地时区）：详情抽屉空间足够，不再省略日期。 */
function fmtTime(iso?: string): string {
  if (!iso) return '-'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const p2 = (n: number) => String(n).padStart(2, '0')
  return (
    `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())} ` +
    `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}.` +
    `${String(d.getMilliseconds()).padStart(3, '0')}`
  )
}

/** 每个分栏的统一标题条。 */
function SectionHeader({ children }: { children: ReactNode }) {
  return (
    <div className="shrink-0 border-b border-subtle px-3 py-2 text-sm font-semibold text-muted">
      {children}
    </div>
  )
}

/**
 * 协议树的一层：可折叠/展开（默认展开），不引树组件库。
 *
 * 展开状态放在本组件内；调用方用包含包号/索引/层名的 key 渲染，
 * 切换包时 React 会重建节点，状态自然复位为「全展开」。
 */
function LayerNode({ layer }: { layer: PacketDetailLayer }) {
  const [open, setOpen] = useState(true)
  return (
    <div className="border-b border-subtle py-1 last:border-b-0">
      <button
        type="button"
        className="flex w-full items-center gap-1 rounded-xs px-1 text-left text-sm font-semibold text-fg hover:bg-elevated"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        title={open ? '折叠' : '展开'}
      >
        <span className="w-3 shrink-0 text-dim">{open ? '▾' : '▸'}</span>
        <span className="min-w-0 break-words">{layer.name}</span>
      </button>
      {open && (
        <div className="mt-1 pl-5">
          {layer.fields.length === 0 ? (
            <div className="text-xs text-dim">（无字段）</div>
          ) : (
            layer.fields.map((f, i) => (
              <div key={`${f.k}-${i}`} className="mono flex gap-2 text-xs leading-relaxed">
                <span className="shrink-0 text-muted">{f.k}</span>
                <span className="shrink-0 text-dim">=</span>
                <span className="min-w-0 break-all text-fg">{f.v}</span>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  )
}

/** 加载中的三栏骨架 + 文案。 */
function LoadingSkeleton() {
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3">
      <div className="flex min-h-0 flex-1 gap-3">
        <section className="panel-surface flex min-h-0 w-2/5 flex-col overflow-hidden">
          <SectionHeader>协议分层</SectionHeader>
          <div className="min-h-0 flex-1 space-y-2 overflow-hidden p-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="h-4 rounded-xs bg-elevated" />
            ))}
          </div>
        </section>
        <section className="panel-surface flex min-h-0 flex-1 flex-col overflow-hidden">
          <SectionHeader>十六进制</SectionHeader>
          <div className="min-h-0 flex-1 space-y-2 overflow-hidden p-3">
            {Array.from({ length: 10 }).map((_, i) => (
              <div key={i} className="h-4 rounded-xs bg-elevated" />
            ))}
          </div>
        </section>
      </div>
      <section className="panel-surface flex flex-col overflow-hidden" style={{ maxHeight: '35%' }}>
        <SectionHeader>载荷</SectionHeader>
        <div className="min-h-0 flex-1 overflow-auto p-3 text-dim">加载中…</div>
      </section>
    </div>
  )
}

/** 已加载完成的三栏视图。 */
function DetailBody({ detail }: { detail: PacketDetailData }) {
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3">
      <div className="flex min-h-0 flex-1 gap-3">
        {/* 协议分层：每层可折叠，默认全展开 */}
        <section className="panel-surface flex min-h-0 w-2/5 flex-col overflow-hidden">
          <SectionHeader>协议分层</SectionHeader>
          <div className="min-h-0 flex-1 overflow-auto p-2">
            {detail.layers.length === 0 ? (
              <div className="text-dim">无协议层</div>
            ) : (
              detail.layers.map((layer, i) => (
                <LayerNode key={`${detail.no}-${i}-${layer.name}`} layer={layer} />
              ))
            )}
          </div>
        </section>

        {/* 十六进制：保留后端每行格式；whitespace-pre 保住连续空格对齐，可横向滚动 */}
        <section className="panel-surface flex min-h-0 flex-1 flex-col overflow-hidden">
          <SectionHeader>十六进制</SectionHeader>
          <div className="min-h-0 flex-1 overflow-auto p-2">
            {detail.hex.length === 0 ? (
              <div className="text-dim">无数据</div>
            ) : (
              <pre className="mono m-0 whitespace-pre text-xs leading-relaxed">
                {detail.hex.join('\n')}
              </pre>
            )}
          </div>
        </section>
      </div>

      {/* 载荷：保留换行；截断时在末尾提示 */}
      <section className="panel-surface flex flex-col overflow-hidden" style={{ maxHeight: '35%' }}>
        <SectionHeader>载荷</SectionHeader>
        <div className="min-h-0 flex-1 overflow-auto p-3">
          {detail.payload_text ? (
            <pre className="mono m-0 whitespace-pre-wrap break-words text-xs leading-relaxed">
              {detail.payload_text}
            </pre>
          ) : (
            <div className="text-dim">无载荷</div>
          )}
          {detail.payload_truncated && (
            <div className="mt-2 text-xs text-warn">载荷已截断（仅显示前 8 KB）</div>
          )}
        </div>
      </section>
    </div>
  )
}

export function PacketDetail({
  packet,
  onClose,
}: {
  packet: PacketRef
  onClose: () => void
}) {
  const { captureId, no } = packet
  const [status, setStatus] = useState<DetailStatus>('loading')
  const [detail, setDetail] = useState<PacketDetailData | null>(null)
  const [error, setError] = useState('')

  // 请求序号：即使中止失败/响应已排队，晚到的旧响应也不能覆盖新状态。
  const seqRef = useRef(0)

  // ESC 关闭（只在抽屉挂载期间监听，关闭即移除）。
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [onClose])

  useEffect(() => {
    const seq = ++seqRef.current

    // 防御非法包号（调用方应保证 no > 0）：不发请求，直接当作不存在。
    if (!captureId || !Number.isFinite(no) || no <= 0) {
      setDetail(null)
      setError('')
      setStatus('missing')
      return
    }

    const cached = readCachedPacket(captureId, no)
    if (cached) {
      setDetail(cached)
      setError('')
      setStatus('done')
      return
    }

    const ctrl = new AbortController()
    setDetail(null)
    setError('')
    setStatus('loading')

    fetchPacketDetail(captureId, no, ctrl.signal)
      .then((d) => {
        if (ctrl.signal.aborted || seq !== seqRef.current) return
        writeCachedPacket(captureId, no, d)
        setDetail(d)
        setStatus('done')
      })
      .catch((e) => {
        if (ctrl.signal.aborted || seq !== seqRef.current) return
        // 404：包/文件已被移除（后端返回 {"error":"not found"}），给更清晰的固定文案。
        if (e instanceof ApiError && e.status === 404) {
          setDetail(null)
          setStatus('missing')
          return
        }
        setError(e instanceof Error ? e.message : String(e))
        setStatus('error')
      })

    return () => ctrl.abort()
  }, [captureId, no])

  const meta =
    status === 'done' && detail ? `${fmtTime(detail.time)} · ${detail.cap_len} 字节` : ''

  return (
    <>
      {/* 遮罩只在抽屉打开时渲染；点击关闭。半透明用容器 opacity，避免写死颜色。 */}
      <div
        className="fixed inset-0 z-40"
        style={{ backgroundColor: 'var(--bg-app)', opacity: 0.72 }}
        onClick={onClose}
        aria-hidden="true"
      />

      <aside
        role="dialog"
        aria-modal="true"
        aria-label={`第 ${no} 个包详情`}
        className="fixed right-0 top-0 z-50 flex h-full flex-col border-l border-strong bg-panel"
        style={{ width: 'min(90vw, 1100px)' }}
      >
        <div className="flex shrink-0 items-center justify-between gap-2 border-b border-subtle px-4 py-3">
          <div className="min-w-0">
            <h2 className="truncate text-lg font-semibold">包详情：第 {no} 个包</h2>
            {meta && <div className="mono text-dim">{meta}</div>}
          </div>
          <button
            type="button"
            className="shrink-0 rounded-sm border border-subtle px-2 py-1 text-sm text-fg hover:bg-elevated"
            onClick={onClose}
            title="关闭（ESC）"
          >
            关闭
          </button>
        </div>

        <div className="flex min-h-0 flex-1 flex-col p-4">
          {status === 'loading' && <LoadingSkeleton />}

          {status === 'error' && <div className="sev-danger">{error || '加载失败'}</div>}

          {status === 'missing' && <div className="text-dim">该包不存在或文件已被移除</div>}

          {status === 'done' && detail && <DetailBody detail={detail} />}
        </div>
      </aside>
    </>
  )
}
