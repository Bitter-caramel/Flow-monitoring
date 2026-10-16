/**
 * 后端 API 客户端（轻量，不引第三方请求库）。
 *
 * 面板通过这里访问后端；所有请求走 Vite 代理（/api → Go 后端）。
 */

export interface CaptureRecord {
  id: string
  name: string
  format: string
  link_type: number
  packet_count: number
  byte_size: number
  file_path: string
  sha256: string
  first_seen?: string
  last_seen?: string
  imported_at: string
}

export interface PacketRecord {
  capture_id: string
  no: number
  time?: string
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  proto: string
  info: string
  cap_len: number
  orig_len: number
}

export interface PageResult<T> {
  items: T[]
  total: number
  offset: number
  limit: number
}

/** 上传 pcap 文件（multipart）。 */
export async function importCapture(file: File, name?: string): Promise<CaptureRecord> {
  const form = new FormData()
  form.append('file', file)
  if (name) form.append('name', name)
  const resp = await fetch('/api/v1/captures/import', { method: 'POST', body: form })
  if (!resp.ok) throw new Error(await resp.text())
  return resp.json()
}

/** 列出 captures。 */
export async function listCaptures(offset = 0, limit = 50): Promise<PageResult<CaptureRecord>> {
  const resp = await fetch(`/api/v1/captures?offset=${offset}&limit=${limit}`)
  if (!resp.ok) throw new Error(await resp.text())
  return resp.json()
}

/** 列出某 capture 的包。 */
export async function listPackets(
  captureId: string,
  offset = 0,
  limit = 100,
): Promise<PageResult<PacketRecord>> {
  const resp = await fetch(
    `/api/v1/captures/${captureId}/packets?offset=${offset}&limit=${limit}`,
  )
  if (!resp.ok) throw new Error(await resp.text())
  return resp.json()
}

/**
 * 模块控制面视图（GET /api/modules 数组元素）。
 * 字段对齐后端 internal/kernel/modulecontrol.ModuleView 的 JSON tag，
 * 前端只声明自己会用的字段（多出来的字段忽略即可）。
 */
export interface ModuleView {
  id: string
  name: string
  version: string
  layer: string
  core: boolean
  enabled: boolean
  /** 运行态：后端 12-3 起可能为 "unknown"/其他值，这里只透传。 */
  state?: string
}

/** 自检发现（对齐后端 registry.Issue）。 */
export interface SelfCheckIssue {
  code: string
  module_id?: string
  message: string
}

/**
 * 自检报告（GET /api/modules/selfcheck）。
 * 对齐后端 registry.SelfCheckReport：ok == len(errors)==0；errors/warnings 为空时字段缺省。
 */
export interface SelfCheckReport {
  ok: boolean
  errors?: SelfCheckIssue[]
  warnings?: SelfCheckIssue[]
  core: string[]
  enabled: string[]
}

/**
 * 带超时的 JSON GET。
 *
 * ★ 与面板用的原语保持一致（不引第三方请求库）：仍是原生 fetch。
 * 超时用 AbortController 触发（默认 3s），超时/网络错误/非 2xx 一律抛 Error，
 * 由调用方决定如何呈现（状态栏据此显示"后端未连接"），绝不产生未捕获的 rejection。
 */
async function getJSON<T>(path: string, timeoutMs = 3000): Promise<T> {
  const ctrl = new AbortController()
  const timer = window.setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const resp = await fetch(path, {
      signal: ctrl.signal,
      headers: { Accept: 'application/json' },
    })
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status} ${resp.statusText}`)
    }
    return (await resp.json()) as T
  } finally {
    window.clearTimeout(timer)
  }
}

/** 列出后端模块（GET /api/modules）。 */
export function listModules(timeoutMs = 3000): Promise<ModuleView[]> {
  return getJSON<ModuleView[]>('/api/modules', timeoutMs)
}

/** 读取后端自检报告（GET /api/modules/selfcheck）。 */
export function getSelfCheck(timeoutMs = 3000): Promise<SelfCheckReport> {
  return getJSON<SelfCheckReport>('/api/modules/selfcheck', timeoutMs)
}
