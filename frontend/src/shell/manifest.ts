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
  /** 层级，用于分组展示。 */
  layer: PanelLayer
  /** 导航图标（emoji 或短字符，轻量 UI 不用图标库）。 */
  icon?: string
}

/** 语义化版本比较：a 是否兼容 b（同 major 且 minor >=）。 */
export function isCompatible(impl: string, want: string): boolean {
  const [aMaj, aMin] = impl.split('.').map(Number)
  const [bMaj, bMin] = want.split('.').map(Number)
  if (aMaj !== bMaj) return false
  if (aMin < bMin) return false
  return true
}
