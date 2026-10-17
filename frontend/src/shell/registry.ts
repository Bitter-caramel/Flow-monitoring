/**
 * 面板注册表（Panel Registry）。
 *
 * 对应后端 registry 包：管理"有哪些面板、谁依赖谁、按序装配"。
 * shell 只读注册表渲染导航与容器，不感知具体面板实现。
 *
 * 生命周期（当前为同进程 React 组件注册，参考 Cordis 的 mount 语义）：
 *   register（挂载声明）→ shell 装配（拓扑排序）→ 渲染选中面板 → 卸载由 React 管理
 */
import type { ComponentType } from 'react'
import type { PanelLayer, PanelManifest } from './manifest'

/** 面板插件 = manifest + React 组件实现。 */
export interface PanelPlugin {
  manifest: PanelManifest
  component: ComponentType
}

/** 注册表错误。 */
export class PanelRegistryError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'PanelRegistryError'
  }
}

/** 面板注册表。 */
class PanelRegistry {
  private panels = new Map<string, PanelPlugin>()

  /**
   * 已启用的后端模块 ID；null = 尚未加载/离线（此时一律视为可用，不许因为不知道就全灰）。
   * ★ 只影响 isAvailable()，不影响 list/query/listByLayer 的返回（入口置灰而非消失）。
   */
  private enabledModuleIds: string[] | null = null

  /**
   * 更新已启用的模块集合。
   * ids === null 代表后端状态未知（加载中/离线）⇒ 所有面板可用。
   */
  setEnabledModules(ids: string[] | null): void {
    this.enabledModuleIds = ids === null ? null : [...new Set(ids)]
  }

  /**
   * 面板是否可用（唯一可用性规则，导航与工作区共用）。
   *   - manifest.moduleId 缺省 ⇒ true（与模块无关，永远可用）；
   *   - 模块集合未知（null）⇒ true（不因离线而全灰）；
   *   - 模块集合已知 ⇒ 该 moduleId 在启用集合中。
   */
  isAvailable(pluginOrManifest: PanelPlugin | PanelManifest): boolean {
    const manifest = 'manifest' in pluginOrManifest ? pluginOrManifest.manifest : pluginOrManifest
    const { moduleId } = manifest
    if (!moduleId) return true
    if (this.enabledModuleIds === null) return true
    return this.enabledModuleIds.includes(moduleId)
  }

  /**
   * 注册一个面板插件。
   *
   * 默认：重复 id 视为冲突（抛错），保护内置面板不被误覆盖。
   * replace=true 时替换已有面板（可替换性：用户用同名面板覆盖内置实现）。
   */
  register(plugin: PanelPlugin, replace = false): void {
    const { id } = plugin.manifest
    if (!id) {
      throw new PanelRegistryError('panel manifest id is empty')
    }
    if (this.panels.has(id) && !replace) {
      throw new PanelRegistryError(`panel id conflict: ${id}`)
    }
    this.panels.set(id, plugin)
  }

  /** 查询面板。 */
  query(id: string): PanelPlugin | undefined {
    return this.panels.get(id)
  }

  /** 列出所有面板（按 id 排序，稳定输出）。 */
  list(): PanelPlugin[] {
    return [...this.panels.values()].sort((a, b) =>
      a.manifest.id.localeCompare(b.manifest.id),
    )
  }

  /** 按层级分组（导航渲染用）。 */
  listByLayer(): Map<PanelLayer, PanelPlugin[]> {
    const groups = new Map<PanelLayer, PanelPlugin[]>()
    for (const p of this.list()) {
      const layer = p.manifest.layer
      const arr = groups.get(layer) ?? []
      arr.push(p)
      groups.set(layer, arr)
    }
    return groups
  }

  /**
   * 拓扑排序（依赖在前），返回面板 id 顺序。
   * 依赖未注册或循环依赖时抛错。
   */
  topologicalSort(): string[] {
    const ids = [...this.panels.keys()]

    // 校验依赖存在
    for (const p of this.panels.values()) {
      for (const dep of p.manifest.depends ?? []) {
        if (!this.panels.has(dep)) {
          throw new PanelRegistryError(
            `panel ${p.manifest.id} depends on unregistered ${dep}`,
          )
        }
      }
    }

    const inDegree = new Map<string, number>()
    const dependents = new Map<string, string[]>()
    for (const id of ids) {
      const deps = this.panels.get(id)!.manifest.depends ?? []
      inDegree.set(id, deps.length)
      for (const dep of deps) {
        const arr = dependents.get(dep) ?? []
        arr.push(id)
        dependents.set(dep, arr)
      }
    }

    const queue = [...inDegree.entries()]
      .filter(([, deg]) => deg === 0)
      .map(([id]) => id)
      .sort()

    const result: string[] = []
    while (queue.length > 0) {
      const cur = queue.shift()!
      result.push(cur)
      for (const child of (dependents.get(cur) ?? []).sort()) {
        const deg = inDegree.get(child)! - 1
        inDegree.set(child, deg)
        if (deg === 0) queue.push(child)
      }
      queue.sort()
    }

    if (result.length !== ids.length) {
      const stuck = [...inDegree.entries()]
        .filter(([, deg]) => deg > 0)
        .map(([id]) => id)
      throw new PanelRegistryError(`cyclic panel dependency: ${stuck.join(', ')}`)
    }
    return result
  }
}

/** 全局默认注册表（面板模块在导入时自注册）。 */
export const panelRegistry = new PanelRegistry()

/** 更新全局默认注册表的已启用模块集合（null = 状态未知/离线，全部可用）。 */
export function setEnabledModules(ids: string[] | null): void {
  panelRegistry.setEnabledModules(ids)
}

/** 判断面板/ manifest 是否可用（全局默认注册表，唯一可用性规则）。 */
export function isAvailable(pluginOrManifest: PanelPlugin | PanelManifest): boolean {
  return panelRegistry.isAvailable(pluginOrManifest)
}

/** 面板自注册入口（面板模块调用，等价后端的 init() 注册）。 */
export function registerPanel(
  manifest: PanelManifest,
  component: ComponentType,
  replace = false,
): void {
  panelRegistry.register({ manifest, component }, replace)
}
