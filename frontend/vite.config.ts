import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// 前端开发服务器配置
// 后端 API 通过 /api 前缀代理到 Go 后端（默认 :18080）
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:18080',
        changeOrigin: true,
      },
      '/healthz': {
        target: 'http://127.0.0.1:18080',
        changeOrigin: true,
      },
    },
  },
})
