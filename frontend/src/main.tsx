import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
// 令牌三层 + 基础层（顺序固定：tokens → theme → density → base）
import './styles/tokens.css'
import './styles/theme.css'
import './styles/density.css'
import './styles/base.css'
import { applyStoredPreferences } from './shell/theme'
import { App } from './shell/App'

// 导入面板模块 → 触发各自的自注册（registerPanel）
// 新增面板只需在此追加一行 import，无需改 shell
import './panels/capture-import'
import './panels/packet-list'
import './panels/situation'
import './panels/analysis-runs'
import './panels/module-graph'
import './panels/alert-list'

// ★ 首帧前应用主题/密度：从 localStorage 读取已存偏好（键名见 shell/theme.ts：
//   fm.theme / fm.density），写入 documentElement.dataset，避免"先深后浅"的闪烁（FOUC）。
applyStoredPreferences()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
