import { useEffect, type ReactNode } from 'react'

/**
 * 自研确认对话框（不引第三方依赖）。
 *
 * 交互契约：
 *   - 遮罩 + 卡片 + 取消/确认；点遮罩或按 Esc 取消；
 *   - danger=true 时确认按钮用语义危险色（--danger）；
 *   - busy=true 时两个按钮都禁用、确认按钮文案变为“处理中…”；
 *   - confirmDisabled=true 时只禁用确认按钮（如影响面 can_disable=false）；
 *   - 样式只引用语义令牌（bg-panel / border-strong / text-fg / bg-danger …）。
 */
export interface ConfirmDialogProps {
  /** 是否显示；false 时不渲染任何内容。 */
  open: boolean
  /** 对话框标题（模块启停用“停用 <name>”/“启用 <name>”）。 */
  title: string
  /** 正文内容（影响面、阻塞原因、错误等由调用方决定）。 */
  children?: ReactNode
  /** 确认按钮文案，默认“确认”。 */
  confirmLabel?: string
  /** 取消按钮文案，默认“取消”。 */
  cancelLabel?: string
  /** 危险操作：确认按钮使用 --danger。 */
  danger?: boolean
  /** 请求进行中：禁用按钮并显示“处理中…”。 */
  busy?: boolean
  /** 仅禁用确认按钮（取消仍可用）。 */
  confirmDisabled?: boolean
  onConfirm: () => void
  onCancel: () => void
}

export function ConfirmDialog({
  open,
  title,
  children,
  confirmLabel = '确认',
  cancelLabel = '取消',
  danger = false,
  busy = false,
  confirmDisabled = false,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  // Esc 取消（busy 期间忽略，避免请求还在跑就关掉）。
  useEffect(() => {
    if (!open) return
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape' && !busy) onCancel()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [open, busy, onCancel])

  if (!open) return null

  const confirmColor = danger ? 'bg-danger text-accent-fg' : 'bg-accent text-accent-fg'

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-app/70 p-4"
      onMouseDown={(e) => {
        // 只有点到遮罩本身（不是卡片内部）才取消。
        if (e.target === e.currentTarget && !busy) onCancel()
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="flex w-full max-w-lg flex-col gap-3 rounded-md border border-strong bg-panel p-4 text-fg"
      >
        <h2 className="text-base font-semibold">{title}</h2>

        <div className="flex flex-col gap-2 text-sm text-muted">{children}</div>

        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            disabled={busy}
            onClick={onCancel}
            className="rounded-sm border border-subtle bg-elevated px-3 py-1.5 text-base text-fg hover:border-strong disabled:cursor-not-allowed disabled:opacity-50"
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            disabled={busy || confirmDisabled}
            onClick={onConfirm}
            className={`rounded-sm px-3 py-1.5 text-base hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50 ${confirmColor}`}
          >
            {busy ? '处理中…' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}
