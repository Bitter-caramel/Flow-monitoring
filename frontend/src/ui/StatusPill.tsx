/**
 * 状态标签（小圆角 + 语义色）。
 *
 * ★ 颜色一律引用语义令牌：ok → --ok、warn → --warn、danger → --danger、
 *   info → --accent、dim → --fg-dim；不写死任何色值。
 * ★ 底色 / 边框由 `color-mix` 从同一令牌派生，保证主题切换时一起变化。
 */
export type StatusKind = 'ok' | 'warn' | 'danger' | 'info' | 'dim'

/** 语义种类 → CSS 令牌（仅 var(--…)，无字面量颜色）。 */
const TOKEN: Record<StatusKind, string> = {
  ok: 'var(--ok)',
  warn: 'var(--warn)',
  danger: 'var(--danger)',
  info: 'var(--accent)',
  dim: 'var(--fg-dim)',
}

export function StatusPill({ kind, label }: { kind: StatusKind; label: string }) {
  const color = TOKEN[kind]
  return (
    <span
      className="inline-flex items-center rounded-sm border px-1.5 py-0.5 text-xs whitespace-nowrap"
      style={{
        color,
        borderColor: `color-mix(in srgb, ${color} 45%, transparent)`,
        backgroundColor: `color-mix(in srgb, ${color} 14%, transparent)`,
      }}
    >
      {label}
    </span>
  )
}
