/**
 * 面板插件契约（Panel Contract）。
 *
 * 对应后端 registry/contract 的理念：每个前端面板都是一个插件，
 * 通过 manifest 声明身份 + 能力 + 依赖，注册到面板注册表，由 shell 装配。
 *
 * "万物皆可替换"：两个面板注册相同 id 时，后注册者替换先注册者（可替换性）。
 * 参考 DSH 的 Cordis 插件模型：Service Definition（本文件的 manifest 类型）
 * / Service Provider（面板组件实现）/ Consumer（shell 消费注册表）。
 */

/** 面板层级（对应后端 registry.Layer）。 */
export type PanelLayer = 'L0' | 'L1' | 'L2' | 'L3'

/** 工作台：前端导航的一级分类（静态分析 / 动态分析 / 控制台）。 */
export type Workbench = 'static' | 'live' | 'console'

/** 工作台固定顺序（顶栏 tab 与默认值按此顺序）。 */
export const WORKBENCHES: readonly Workbench[] = ['static', 'live', 'console']

/** 工作台中文名（顶栏 tab / 无障碍标签用）。 */
export const WORKBENCH_LABELS: Record<Workbench, string> = {
  static: '静态分析',
  live: '动态分析',
  console: '控制台',
}

/** 面板 manifest —— 插件的"身份证"。 */
export interface PanelManifest {
  /** 唯一标识，如 "panels.packet-list"（命名约定 domain.name）。 */
  id: string
  /** 显示名（导航栏/标题用）。 */
  name: string
  /** 语义化版本 "1.0.0"。 */
  version: string
  /** 一句话说明（导航 tooltip / 管理页）。 */
  description?: string
  /** 依赖的面板能力 ID（可选，shell 装配时校验）。 */
  depends?: string[]
  /**
   * 层级。
   * ★ 保留供诊断/未来使用，导航已改用 workbenches；不要再据此分组导航。
   */
  layer: PanelLayer
  /** 所属工作台（必填）；一个面板可同时出现在多个工作台。 */
  workbenches: Workbench[]
  /** 工作台内的分组标题（可选；缺省归入「其它」）。 */
  group?: string
  /** 导航图标（emoji 或短字符，轻量 UI 不用图标库）。 */
  icon?: string
  /**
   * 所属后端模块 ID（如 "modules.query"）。
   * 缺省 = 与模块无关（宿主面板），永远可用；
   * 非缺省时由后端 /api/modules 的 enabled 状态决定入口是否可用（置灰而非隐藏）。
   */
  moduleId?: string
}

/** 语义化版本比较：a 是否兼容 b（同 major 且 minor >=）。 */
export function isCompatible(impl: string, want: string): boolean {
  const [aMaj, aMin] = impl.split('.').map(Number)
  const [bMaj, bMin] = want.split('.').map(Number)
  if (aMaj !== bMaj) return false
  if (aMin < bMin) return false
  return true
}
