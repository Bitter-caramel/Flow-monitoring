/**
 * 共用的「包详情」抽屉。
 *
 * ★ 只在传入 packet 且组件挂载时才请求一次；关闭/切换包时中止在途请求。
 * ★ 命中 packetCache（5 分钟）则完全不发请求。
 * ★ 请求永远只取 1 条：offset=no-1&limit=1；空列表 ⇒「该包不存在」。
 */
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { fetchPacket, type PacketRecord } from '../api'
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

function fmtEndpoint(ip: string, port: number): string {
  if (!ip) return '-'
  return port > 0 ? `${ip}:${port}` : ip
}

/** 详情里的一行：左标签、右值。 */
function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex gap-3 border-b border-subtle py-2 last:border-b-0">
      <span className="w-24 shrink-0 text-dim">{label}</span>
      <span className="min-w-0 flex-1 break-words">{children}</span>
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
  const [record, setRecord] = useState<PacketRecord | null>(null)
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
      setRecord(null)
      setError('')
      setStatus('missing')
      return
    }

    const cached = readCachedPacket(captureId, no)
    if (cached) {
      setRecord(cached)
      setError('')
      setStatus('done')
      return
    }

    const ctrl = new AbortController()
    setRecord(null)
    setError('')
    setStatus('loading')

    fetchPacket(captureId, no, ctrl.signal)
      .then((rec) => {
        if (ctrl.signal.aborted || seq !== seqRef.current) return
        if (!rec) {
          setRecord(null)
          setStatus('missing')
          return
        }
        writeCachedPacket(captureId, no, rec)
        setRecord(rec)
        setStatus('done')
      })
      .catch((e) => {
        if (ctrl.signal.aborted || seq !== seqRef.current) return
        setError(e instanceof Error ? e.message : String(e))
        setStatus('error')
      })

    return () => ctrl.abort()
  }, [captureId, no])

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
        style={{ width: 'min(32rem, 92vw)' }}
      >
        <div className="flex shrink-0 items-center justify-between gap-2 border-b border-subtle px-4 py-3">
          <h2 className="text-lg font-semibold">第 {no} 个包</h2>
          <button
            type="button"
            className="rounded-sm border border-subtle px-2 py-1 text-sm text-fg hover:bg-elevated"
            onClick={onClose}
            title="关闭（ESC）"
          >
            关闭
          </button>
        </div>

        <div className="flex-1 overflow-auto p-4">
          {status === 'loading' && <div className="text-dim">加载中…</div>}

          {status === 'error' && (
            <div className="sev-danger">{error || '加载失败'}</div>
          )}

          {status === 'missing' && <div className="text-dim">该包不存在</div>}

          {status === 'done' && record && (
            <div className="panel-surface px-3 py-1">
              <Field label="时间">
                <span className="mono" title={record.time}>
                  {fmtTime(record.time)}
                </span>
              </Field>
              <Field label="源 → 目的">
                <span className="mono">
                  {fmtEndpoint(record.src_ip, record.src_port)}
                  <span className="text-dim"> → </span>
                  {fmtEndpoint(record.dst_ip, record.dst_port)}
                </span>
              </Field>
              <Field label="协议">
                <span>{record.proto || '-'}</span>
              </Field>
              <Field label="INFO">
                <span className="mono whitespace-normal break-words">
                  {record.info || '-'}
                </span>
              </Field>
              <Field label="抓包长度">
                <span className="mono">{record.cap_len}</span>
              </Field>
              <Field label="原始长度">
                <span className="mono">{record.orig_len}</span>
              </Field>
            </div>
          )}
        </div>
      </aside>
    </>
  )
}
