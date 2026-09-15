import { useEffect, useState } from 'react'
import { listCaptures, listPackets, type CaptureRecord, type PacketRecord } from '../../api'

const PAGE_SIZE = 100

/**
 * 包列表面板。
 *
 * 功能：
 *   1. 下拉选择 capture
 *   2. 分页展示包列表（No/时间/源→目的/协议/长度/INFO）
 *
 * 实质功能：真实调 query-api 分页取包，不做假数据。
 */
export function PacketListPanel() {
  const [captures, setCaptures] = useState<CaptureRecord[]>([])
  const [captureId, setCaptureId] = useState('')
  const [packets, setPackets] = useState<PacketRecord[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [error, setError] = useState('')

  // 加载 capture 列表
  useEffect(() => {
    listCaptures(0, 100)
      .then((res) => {
        setCaptures(res.items)
        if (res.items.length > 0 && !captureId) {
          setCaptureId(res.items[0].id)
        }
      })
      .catch((e) => setError(String(e)))
  }, [captureId])

  // 加载包列表
  useEffect(() => {
    if (!captureId) return
    listPackets(captureId, offset, PAGE_SIZE)
      .then((res) => {
        setPackets(res.items)
        setTotal(res.total)
      })
      .catch((e) => setError(String(e)))
  }, [captureId, offset])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1

  return (
    <div className="panel">
      <div className="panel-header">
        <h2 className="panel-title">包列表</h2>
        <span className="panel-subtitle">
          共 {total} 包 · 第 {currentPage}/{totalPages} 页
        </span>
      </div>

      <div>
        <select
          value={captureId}
          onChange={(e) => {
            setCaptureId(e.target.value)
            setOffset(0)
          }}
          style={{ padding: '6px 10px', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)' }}
        >
          {captures.length === 0 && <option value="">暂无 capture</option>}
          {captures.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}（{c.packet_count} 包）
            </option>
          ))}
        </select>
      </div>

      {error && <div className="error">{error}</div>}

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>No.</th>
              <th>时间</th>
              <th>源</th>
              <th>目的</th>
              <th>协议</th>
              <th>长度</th>
              <th>Info</th>
            </tr>
          </thead>
          <tbody>
            {packets.length === 0 ? (
              <tr>
                <td colSpan={7} className="info">
                  无数据
                </td>
              </tr>
            ) : (
              packets.map((p) => (
                <tr key={p.no}>
                  <td className="mono">{p.no}</td>
                  <td className="mono">{p.time ? new Date(p.time).toLocaleTimeString('zh-CN', { hour12: false }) : '-'}</td>
                  <td className="mono">{formatEndpoint(p.src_ip, p.src_port)}</td>
                  <td className="mono">{formatEndpoint(p.dst_ip, p.dst_port)}</td>
                  <td>{p.proto}</td>
                  <td className="mono">{p.cap_len}</td>
                  <td className="mono" style={{ whiteSpace: 'normal' }}>{p.info}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <button className="btn" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
          上一页
        </button>
        <button className="btn" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>
          下一页
        </button>
      </div>
    </div>
  )
}

function formatEndpoint(ip: string, port: number): string {
  if (port > 0) return `${ip}:${port}`
  return ip
}
