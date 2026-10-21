/**
 * 工作台上下文 —— 让面板（含深层子组件）知道"自己当前在哪个工作台"。
 *
 * ★ App 用 <WorkbenchProvider value={workbench}> 包住工作区与侧边栏；
 *   未包裹时 useWorkbench() 明确抛错（不静默返回默认值，避免面板悄悄走错
 *   工作台语义）。抛错发生在面板渲染期，由 PanelErrorBoundary 兜住，
 *   不会把整个控制台打白。
 */
import { createContext, useContext } from 'react'
import type { ReactNode } from 'react'
import type { Workbench } from './manifest'

/** null 表示"没有 Provider"，与合法值区分开（三个工作台都是真值字符串）。 */
const WorkbenchContext = createContext<Workbench | null>(null)

export function WorkbenchProvider({
  value,
  children,
}: {
  value: Workbench
  children: ReactNode
}) {
  return <WorkbenchContext.Provider value={value}>{children}</WorkbenchContext.Provider>
}

/** 读取当前工作台；未包裹在 Provider 内时明确抛错（由错误边界兜住）。 */
export function useWorkbench(): Workbench {
  const wb = useContext(WorkbenchContext)
  if (wb === null) {
    throw new Error('useWorkbench 必须在 <WorkbenchProvider> 内使用')
  }
  return wb
}
