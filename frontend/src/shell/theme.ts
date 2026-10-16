/**
 * 主题 / 密度 偏好（theme & density preferences）。
 *
 * 设计文档 §5：令牌三层（tokens → theme → density）+ 组件只读语义令牌。
 * 本文件是"运行时切换开关"的唯一入口：读写 documentElement.dataset 并持久化到 localStorage。
 *
 * ★ localStorage 键名（自定，改动需同步这里）：
 *   - 'fm.theme'   ：'dark' | 'light'          —— 默认 'dark'
 *   - 'fm.density' ：'compact' | 'normal' | 'comfortable' —— 默认 'compact'
 *
 * ★ 首帧前应用：main.tsx 在 createRoot(...).render(...) 之前调用 applyStoredPreferences()，
 *   避免"先深后浅"的闪烁（FOUC）。主题/密度切换 = 改 dataset，运行时零重渲染。
 *
 * 说明：localStorage 在隐私模式/禁用时会抛异常，因此读写一律 try/catch；
 * 拿不到就退回默认值（绝不因偏好读写失败而白屏）。
 */

/** 主题：深 / 浅。 */
export type Theme = 'dark' | 'light'

/** 密度：紧凑 / 标准 / 宽松（对应 density.css 的 data-density）。 */
export type Density = 'compact' | 'normal' | 'comfortable'

/** localStorage 键名。 */
export const THEME_KEY = 'fm.theme'
export const DENSITY_KEY = 'fm.density'

/** 默认值：深色 + 紧凑（分析控制台，设计文档 §1 / §5）。 */
export const DEFAULT_THEME: Theme = 'dark'
export const DEFAULT_DENSITY: Density = 'compact'

/** 可选值（TopBar 渲染顺序即此顺序）。 */
export const THEMES: readonly Theme[] = ['dark', 'light']
export const DENSITIES: readonly Density[] = ['compact', 'normal', 'comfortable']

/** 密度中文标签（界面展示用；密度本身仍是 token 名）。 */
export const DENSITY_LABELS: Record<Density, string> = {
  compact: '紧凑',
  normal: '标准',
  comfortable: '宽松',
}

/** 类型守卫：取值是否为合法主题。 */
export function isTheme(v: unknown): v is Theme {
  return v === 'dark' || v === 'light'
}

/** 类型守卫：取值是否为合法密度。 */
export function isDensity(v: unknown): v is Density {
  return v === 'compact' || v === 'normal' || v === 'comfortable'
}

/** 读已存主题（失败/非法 → 默认）。 */
export function readStoredTheme(): Theme {
  try {
    const v = window.localStorage.getItem(THEME_KEY)
    return isTheme(v) ? v : DEFAULT_THEME
  } catch {
    return DEFAULT_THEME
  }
}

/** 读已存密度（失败/非法 → 默认）。 */
export function readStoredDensity(): Density {
  try {
    const v = window.localStorage.getItem(DENSITY_KEY)
    return isDensity(v) ? v : DEFAULT_DENSITY
  } catch {
    return DEFAULT_DENSITY
  }
}

/** 应用主题：写 documentElement.dataset.theme 并持久化。 */
export function setTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme
  try {
    window.localStorage.setItem(THEME_KEY, theme)
  } catch {
    /* 持久化失败不影响当前会话（dataset 已生效） */
  }
}

/** 应用密度：写 documentElement.dataset.density 并持久化。 */
export function setDensity(density: Density): void {
  document.documentElement.dataset.density = density
  try {
    window.localStorage.setItem(DENSITY_KEY, density)
  } catch {
    /* 同上 */
  }
}

/** 首帧前应用已存偏好（main.tsx 调用；不读不写就退回默认值）。 */
export function applyStoredPreferences(): void {
  document.documentElement.dataset.theme = readStoredTheme()
  document.documentElement.dataset.density = readStoredDensity()
}
