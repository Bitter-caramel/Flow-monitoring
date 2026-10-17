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

/** localStorage 里的控制面 Token 键（不做登录页，只读这里）。 */
const TOKEN_STORAGE_KEY = 'fm.token'

/** 401 时的统一文案。 */
const TOKEN_REQUIRED_MESSAGE = '需要 Token：请在浏览器 localStorage 设置 fm.token'

/**
 * 统一请求头：所有非 GET/HEAD 请求带 CSRF 头；localStorage 有 fm.token 时带 Bearer。
 *
 * ★ 只在请求封装里加，不散落到各面板。
 */
function requestHeaders(method: string): Record<string, string> {
  const headers: Record<string, string> = {}
  if (method !== 'GET' && method !== 'HEAD') {
    headers['X-Flow-Request'] = '1'
  }
  try {
    const token =
      typeof window !== 'undefined' ? window.localStorage.getItem(TOKEN_STORAGE_KEY) : null
    if (token) headers['Authorization'] = `Bearer ${token}`
  } catch {
    // localStorage 不可用（隐私模式等）：忽略，不影响请求。
  }
  return headers
}

/** 非 2xx 统一抛错；401 给出可操作的 Token 提示，其余优先用后端 error 文案。 */
async function throwIfNotOK(resp: Response): Promise<void> {
  if (resp.ok) return
  if (resp.status === 401) {
    throw new Error(TOKEN_REQUIRED_MESSAGE)
  }
  const detail = await readErrorDetail(resp)
  throw new Error(detail || `HTTP ${resp.status} ${resp.statusText}`)
}

/** 上传 pcap 文件（multipart）。 */
export async function importCapture(file: File, name?: string): Promise<CaptureRecord> {
  const form = new FormData()
  form.append('file', file)
  if (name) form.append('name', name)
  const resp = await fetch('/api/v1/captures/import', {
    method: 'POST',
    body: form,
    headers: requestHeaders('POST'),
  })
  await throwIfNotOK(resp)
  return resp.json()
}

/**
 * ★ Go ↔ JS 契约坑（2026-10-17 实测踩到）：Go 的 **nil slice 会被编码成 JSON `null`**，
 * 而后端"查不到行"时就是 nil ⇒ `{"items":null,"total":-1}`。前端若直接 `items.length`
 * 会抛 `TypeError: Cannot read properties of null (reading 'length')`，
 * ★ 而且会把整个控制台打成白屏（面板崩 + 无 error boundary）。
 * ⇒ 所有分页接口统一在这里归一化：items 一定是数组，total 一定是非负数。
 */
function normalizePage<T>(raw: PageResult<T>): PageResult<T> {
  const items = Array.isArray(raw.items) ? raw.items : []
  const total = typeof raw.total === 'number' && raw.total >= 0 ? raw.total : items.length
  return { ...raw, items, total }
}

/** 列出 captures。 */
export async function listCaptures(offset = 0, limit = 50): Promise<PageResult<CaptureRecord>> {
  const resp = await fetch(`/api/v1/captures?offset=${offset}&limit=${limit}`, {
    headers: requestHeaders('GET'),
  })
  await throwIfNotOK(resp)
  return normalizePage<CaptureRecord>(await resp.json())
}

/** 列出某 capture 的包。 */
export async function listPackets(
  captureId: string,
  offset = 0,
  limit = 100,
): Promise<PageResult<PacketRecord>> {
  const resp = await fetch(
    `/api/v1/captures/${captureId}/packets?offset=${offset}&limit=${limit}`,
    { headers: requestHeaders('GET') },
  )
  await throwIfNotOK(resp)
  return normalizePage<PacketRecord>(await resp.json())
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
      headers: { Accept: 'application/json', ...requestHeaders('GET') },
    })
    await throwIfNotOK(resp)
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

/**
 * 存储健康（GET /healthz 的 storage 字段）。
 *
 * available=false 时 err 说明原因（如数据库未连接）；last_check/interval_seconds
 * 用于状态栏 tooltip 或排障，缺省时忽略即可。
 */
export interface HealthStorage {
  available: boolean
  err?: string
  last_check?: string
  interval_seconds?: number
}

/** 后端总体健康（GET /healthz）。storage 可能缺省（旧后端 / 读取失败时）。 */
export interface Health {
  status: string
  storage?: HealthStorage
}

/** 读取后端健康状态（GET /healthz）。复用 getJSON 的 3s 超时封装。 */
export function fetchHealth(timeoutMs = 3000): Promise<Health> {
  return getJSON<Health>('/healthz', timeoutMs)
}

/**
 * 模块拓扑图节点（GET /api/modules/graph 的 nodes[]）。
 * layer 取值 "L0"|"L1"|"L2"|"L3"；state 取值 "started"|"stopped"|"error"|"unknown"。
 */
export interface GraphNode {
  id: string
  name: string
  version: string
  layer: string
  core: boolean
  enabled: boolean
  provides: string[]
  injects: string[]
  http_base?: string
  binary?: string
  state: string
}

/** 模块拓扑图边：from 消费者 → to 提供者；via 形如 "provides:<能力名>"。 */
export interface GraphEdge {
  from: string
  to: string
  via: string
}

/** 模块拓扑图（GET /api/modules/graph）。 */
export interface ModuleGraph {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

/** 读取模块拓扑图（GET /api/modules/graph）。 */
export function fetchModulesGraph(timeoutMs = 3000): Promise<ModuleGraph> {
  return getJSON<ModuleGraph>('/api/modules/graph', timeoutMs)
}

/**
 * 停用某模块的影响面（GET /api/modules/{id}/impact）。
 *
 * 对齐后端 modulecontrol.Impact：
 *   - core：目标本身是否为核心模块；
 *   - dependents：直接/间接依赖它的模块，按级联关闭顺序给出；
 *   - can_disable：false 表示不可停用（目标是 core，或停它会连带停 core）；
 *   - block_reason：can_disable=false 时的原因，界面原样展示。
 *
 * ★ POST /api/modules/{id}/disable?dry_run=1 返回的是同一结构（200 预演结果，不是错误）。
 */
export interface ModuleImpact {
  id: string
  core: boolean
  dependents: string[]
  /** 插件目录里是否存在该模块的可执行文件（与运行期找二进制的规则一致）。 */
  has_binary: boolean
  can_disable: boolean
  block_reason?: string
}

/** 级联启停里单个模块的一步结果（对齐后端 modulecontrol.StepResult）。 */
export interface CascadeStep {
  id: string
  /** "stop" 或 "start"（后端按实际动作给出）。 */
  action: string
  ok: boolean
  /** ok=false 时的错误原文；成功时后端省略该字段。 */
  err?: string
}

/** 一次级联启停的完整账本（对齐后端 modulecontrol.CascadeResult）。 */
export interface CascadeResult {
  id: string
  enabled: boolean
  /** 实际执行顺序（与 Impact.Dependents 同序）。 */
  steps: CascadeStep[]
  /** 执行成功的模块（启用时只含自己）。 */
  stopped: string[]
  /** 执行失败的模块。 */
  failed: string[]
  /** applied=false 表示没有运行期后端，只改了清单，需要重启生效。 */
  applied: boolean
  restart_hint?: string
}

/** 后端 nil slice 会被编码成 JSON null：统一归一化，避免界面 `.length` 崩溃。 */
function normalizeImpact(raw: ModuleImpact): ModuleImpact {
  return {
    ...raw,
    dependents: Array.isArray(raw.dependents) ? raw.dependents : [],
    has_binary: !!raw.has_binary,
    can_disable: raw.can_disable === true,
  }
}

/** 同上：级联账本里的数组字段一律归一化为数组。 */
function normalizeCascade(raw: CascadeResult): CascadeResult {
  return {
    ...raw,
    steps: Array.isArray(raw.steps) ? raw.steps : [],
    stopped: Array.isArray(raw.stopped) ? raw.stopped : [],
    failed: Array.isArray(raw.failed) ? raw.failed : [],
  }
}

/**
 * 读取非 2xx 响应的后端文案，供界面原样展示。
 *
 * 后端 writeErr 统一返回 {"error": "..."}；Impact 结构则可能带 block_reason。
 * 优先取 error，其次 block_reason，最后退回响应原文 / HTTP 状态。
 */
async function readErrorDetail(resp: Response): Promise<string> {
  let text = ''
  try {
    text = await resp.text()
  } catch {
    return ''
  }
  if (!text) return ''
  try {
    const body = JSON.parse(text) as { error?: unknown; block_reason?: unknown }
    if (typeof body.error === 'string' && body.error) return body.error
    if (typeof body.block_reason === 'string' && body.block_reason) return body.block_reason
  } catch {
    // 非 JSON（如纯文本错误）：保留原文。
  }
  return text
}

/** 带后端错误文案的 JSON POST（不设短超时：级联停模块可能耗时较久）。 */
async function postJSON<T>(path: string): Promise<T> {
  const resp = await fetch(path, {
    method: 'POST',
    headers: { Accept: 'application/json', ...requestHeaders('POST') },
  })
  await throwIfNotOK(resp)
  return (await resp.json()) as T
}

/** 读取停用影响面（GET /api/modules/{id}/impact）。 */
export async function fetchModuleImpact(id: string, timeoutMs = 3000): Promise<ModuleImpact> {
  const raw = await getJSON<ModuleImpact>(
    `/api/modules/${encodeURIComponent(id)}/impact`,
    timeoutMs,
  )
  return normalizeImpact(raw)
}

/** 启用模块（POST /api/modules/{id}/enable）；只启动它自己。 */
export async function postModuleEnable(id: string): Promise<CascadeResult> {
  const raw = await postJSON<CascadeResult>(`/api/modules/${encodeURIComponent(id)}/enable`)
  return normalizeCascade(raw)
}

/**
 * 停用模块（POST /api/modules/{id}/disable）；级联先停依赖它的模块。
 *
 * 409/400 等非 2xx 一律抛出带后端 error/block_reason 文案的 Error，界面原样展示。
 * 注意：级联中某步失败仍可能返回 200，失败明细在 CascadeResult.failed/steps 里。
 */
export async function postModuleDisable(id: string): Promise<CascadeResult> {
  const raw = await postJSON<CascadeResult>(`/api/modules/${encodeURIComponent(id)}/disable`)
  return normalizeCascade(raw)
}
