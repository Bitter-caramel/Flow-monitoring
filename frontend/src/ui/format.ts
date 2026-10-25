/**
 * 展示层格式化纯函数（无副作用、无依赖）。
 *
 * ★ 只做字符串转换；数据获取 / 状态管理不在这里。
 * ★ 数值非法（NaN / 负数 / 缺省）一律返回全角破折号 `—`，
 *   避免把 `NaN`、`0` 之类误当成真实指标展示。
 */

/** 缺省值占位（与各面板原有的 `—` 保持一致）。 */
const DASH = '—'

/**
 * 字节数 → 人类可读（B / KB / MB）。
 *
 * 统一自 analysis-runs / capture-import 原有的两份实现：
 *   B 取整、KB / MB 保留 1 位小数；KB 阈值 1024、MB 阈值 1024²。
 *
 * ★ 0 字节是**真实值**（空抓包、导入失败残留），显示 `0 B`；
 *   只有负数 / NaN / Infinity 才显示 `—`（未知）。
 */
export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return DASH
  if (n === 0) return '0 B'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

/**
 * ISO 时间字符串 → `YYYY-MM-DD HH:MM:SS`（本地时区）。
 *
 * 非法 / 空字符串原样返回，绝不抛错（调用方自行决定是否显示占位）。
 */
export function formatTime(iso: string): string {
  if (!iso) return iso
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const p2 = (v: number) => String(v).padStart(2, '0')
  return (
    `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())} ` +
    `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`
  )
}

/**
 * 毫秒 → `1.2s` / `1m 3s` / `2h 5m`。
 *
 * 不足 1 分钟保留 1 位小数；1 小时以内用「分 + 秒」；超过 1 小时用「时 + 分」。
 * 非法 / 负数返回 `—`。
 */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return DASH
  const totalSeconds = ms / 1000
  if (totalSeconds < 60) return `${totalSeconds.toFixed(1)}s`
  const totalMinutes = Math.floor(totalSeconds / 60)
  const seconds = Math.floor(totalSeconds % 60)
  if (totalMinutes < 60) return `${totalMinutes}m ${seconds}s`
  const hours = Math.floor(totalMinutes / 60)
  const minutes = totalMinutes % 60
  return `${hours}h ${minutes}m`
}

/** 数字 → 千分位（例：1234567 → `1,234,567`）；NaN 返回 `—`。 */
export function formatNumber(n: number): string {
  if (!Number.isFinite(n)) return DASH
  return n.toLocaleString('en-US')
}
