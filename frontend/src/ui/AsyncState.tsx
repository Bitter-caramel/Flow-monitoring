import type { ReactNode } from 'react'

/**
 * 异步面板的三种统一占位：加载中 / 空态 / 错误。
 *
 * ★ 三者共用同一套视觉：居中、`text-dim`（颜色只引用语义令牌，不写死）。
 * ★ 尺寸交给调用方：基础样式不含 flex-1 / 固定高度；
 *   需要铺满容器时由调用方传 `className="flex-1"`，避免和原布局打架。
 */
const BASE = 'flex flex-col items-center justify-center gap-2 px-4 py-6 text-center text-dim'

/** 拼接基础样式与调用方附加样式（不引第三方 className 工具）。 */
function cx(extra?: string): string {
  return extra ? `${BASE} ${extra}` : BASE
}

/** 加载中：默认文案 `加载中…`，可用 label 覆盖为具体动作。 */
export function LoadingState({ label = '加载中…', className }: { label?: string; className?: string }) {
  return (
    <div className={cx(className)} role="status" aria-live="polite">
      {label}
    </div>
  )
}

/** 空态：文案由调用方传入，保持与各面板原有提示一致。 */
export function EmptyState({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cx(className)}>{children}</div>
}

/**
 * 错误态：必须显示**具体错误文案**（Error.message 或原始字符串）；
 * 文案为空时兜底 `出错了`，绝不只写一句「出错了」而丢掉真实原因。
 * onRetry 存在时才渲染「重试」按钮。
 */
export function ErrorView({
  error,
  onRetry,
  className,
}: {
  error: Error | string
  onRetry?: () => void
  className?: string
}) {
  const message = error instanceof Error ? error.message : String(error)
  return (
    <div className={cx(className)} role="alert">
      <span className="text-danger">{message || '出错了'}</span>
      {onRetry && (
        <button
          type="button"
          className="rounded-sm bg-accent px-3 py-1.5 text-base text-accent-fg hover:opacity-90"
          onClick={onRetry}
        >
          重试
        </button>
      )}
    </div>
  )
}
