/**
 * 实时告警面板的数据访问（宿主 GET /api/alerts）。
 *
 * ★ 归一化沿用 api.ts 的约定（见其 normalizePage）：
 *   Go 的 nil slice 会序列化成 JSON null，前端直接 `.length` 会白屏。
 *   这里保证 items 一定是数组、total 一定是非负数。
 *
 * 说明：本任务的硬约束不允许改共享的 api.ts，故在此复刻同一归一化约定，
 * 而不是把告警接口塞进共享客户端；字段名与后端 alerting.Alert 的 JSON tag 一致。
 */

export interface AlertRecord {
  id: number
  rule_id: string
  name: string
  severity: string
  weight: number
  time: string
  src_ip: string
  src_port: number
  dst_ip: string
  dst_port: number
  proto: string
  stream_id: number
  /** 命中包号（capture 帧序号）；旧载荷可能缺省（16-6 起不再在告警列表展示）。 */
  pkt_no?: number
  buffer: string
  offset: number
  snippet: string
  /** 分析任务归属（静态告警用于按证据包隔离实时推送）。 */
  run_id?: string
  mode?: string
  /** 源抓包文件 ID（静态工作台的证据包标识）。 */
  capture_id?: string
}

export interface AlertPage {
  items: AlertRecord[]
  total: number
  page: number
  page_size: number
}

/** 与 api.ts 的 normalizePage 相同的约定：items 必为数组、total 必为非负数。 */
function normalizeAlertPage(raw: Partial<AlertPage> | null | undefined): AlertPage {
  const items = Array.isArray(raw?.items) ? raw.items : []
  const total =
    typeof raw?.total === 'number' && raw.total >= 0 ? raw.total : items.length
  return {
    items,
    total,
    page: typeof raw?.page === 'number' ? raw.page : 1,
    page_size: typeof raw?.page_size === 'number' ? raw.page_size : items.length,
  }
}

/**
 * 拉取一页告警（GET /api/alerts）。
 *
 * sinceID > 0 时只取 id 更大的增量（WS 重连后的补拉用）。
 * mode 非空时附加 `&mode=`，由后端按工作台（live/static）过滤。
 * captureId 非空时附加 `&capture_id=`，由后端按当前证据包过滤（静态工作台）。
 */
export async function fetchAlerts(
  page = 1,
  pageSize = 50,
  sinceID = 0,
  mode?: string,
  captureId?: string,
): Promise<AlertPage> {
  const params = new URLSearchParams({
    page: String(page),
    page_size: String(pageSize),
  })
  if (sinceID > 0) params.set('since_id', String(sinceID))
  if (mode) params.set('mode', mode)
  if (captureId) params.set('capture_id', captureId)

  const resp = await fetch(`/api/alerts?${params.toString()}`, {
    headers: { Accept: 'application/json' },
  })
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status} ${resp.statusText}`)
  }
  return normalizeAlertPage((await resp.json()) as Partial<AlertPage>)
}
