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
