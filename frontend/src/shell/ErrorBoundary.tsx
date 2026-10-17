import { Component, type ErrorInfo, type ReactNode } from 'react'

/**
 * 面板级错误边界。
 *
 * ★ 为什么需要它（2026-10-17 实测事故）：某个面板拿到意外数据（后端返回
 * `{"items":null}` —— Go 的 nil slice 编码成 JSON null）后抛了 TypeError，
 * 而当时**没有 error boundary** ⇒ React 卸载整棵树 ⇒ **整个控制台一片白** ✗。
 * 安全运营控制台不允许"一个面板崩了就不能干活"。
 *
 * ★ 用法：包住工作区的面板挂载点，并**用面板 id 作 key** ——
 * 这样切换面板时会重建边界，错误状态自动复位（不需要手动清）。
 */
interface Props {
  children: ReactNode
  /** 面板名（用于错误提示，可选） */
  label?: string
}

interface State {
  error: Error | null
}

export class PanelErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // 控制台保留完整堆栈，便于排查（生产环境可改为上报）
    console.error('[panel] 渲染失败', error, info.componentStack)
  }

  private reset = () => this.setState({ error: null })

  render() {
    const { error } = this.state
    if (!error) return this.props.children

    const title = this.props.label ? `面板渲染失败：${this.props.label}` : '面板渲染失败'
    return (
      <div className="flex h-full flex-col gap-3 p-4">
        <div className="font-semibold text-danger">{title}</div>
        <div className="text-dim text-xs">
          其他面板不受影响 —— 可直接切到别的面板继续工作；下方是原始错误，便于定位。
        </div>
        <pre className="mono max-h-[50vh] overflow-auto rounded-sm border border-subtle bg-panel p-3 text-xs text-warn">
          {String(error.stack || error.message)}
        </pre>
        <button
          className="self-start rounded-sm bg-accent px-3 py-1.5 text-base text-accent-fg hover:opacity-90"
          onClick={this.reset}
        >
          重试
        </button>
      </div>
    )
  }
}
