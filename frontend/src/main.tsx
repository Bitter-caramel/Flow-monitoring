import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
// 令牌三层 + 基础层（顺序固定：tokens → theme → density → base）
import './styles/tokens.css'
import './styles/theme.css'
import './styles/density.css'
import './styles/base.css'
import { App } from './shell/App'

// 导入面板模块 → 触发各自的自注册（registerPanel）
// 新增面板只需在此追加一行 import，无需改 shell
import './panels/capture-import'
import './panels/packet-list'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
