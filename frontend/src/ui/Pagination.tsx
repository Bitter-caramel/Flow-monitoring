import { formatNumber } from './format'

/**
 * 通用分页条：首页 / 上一页 / 下一页 / 末页 + `第 X / Y 页（共 N 条）`。
 *
 * ★ 只有一页时不渲染任何内容（避免占位 / 一排禁用按钮）。
 * ★ 页码越界自动收敛到 [1, totalPages]；颜色只引用语义令牌。
 */
export function Pagination({
  page,
  pageSize,
  total,
  onChange,
}: {
  page: number
  pageSize: number
  total: number
  onChange: (page: number) => void
}) {
  const safePageSize = Math.max(1, pageSize)
  const totalPages = Math.max(1, Math.ceil(total / safePageSize))
  if (totalPages <= 1) return null

  const current = Math.min(Math.max(1, page), totalPages)
  const atFirst = current <= 1
  const atLast = current >= totalPages
  const buttonClass =
    'rounded-sm bg-accent px-3 py-1.5 text-base text-accent-fg hover:opacity-90 ' +
    'disabled:cursor-not-allowed disabled:opacity-50'

  return (
    <div className="flex flex-wrap items-center gap-2">
      <button type="button" className={buttonClass} disabled={atFirst} onClick={() => onChange(1)}>
        首页
      </button>
      <button
        type="button"
        className={buttonClass}
        disabled={atFirst}
        onClick={() => onChange(current - 1)}
      >
        上一页
      </button>
      <button
        type="button"
        className={buttonClass}
        disabled={atLast}
        onClick={() => onChange(current + 1)}
      >
        下一页
      </button>
      <button
        type="button"
        className={buttonClass}
        disabled={atLast}
        onClick={() => onChange(totalPages)}
      >
        末页
      </button>
      <span className="text-sm text-dim">
        第 {current} / {totalPages} 页（共 {formatNumber(total)} 条）
      </span>
    </div>
  )
}
