import { useCallback, useEffect, useState } from 'react'
import { importCapture, listCaptures, type CaptureRecord } from '../../api'

/**
 * 抓包导入面板。
 *
 * 功能：
 *   1. 选择并上传 pcap/pcapng 文件
 *   2. 展示已导入的 capture 列表
 *
 * 实质功能（不装样子）：上传真实调后端 importer，列表真实调 query-api。
 */
export function CaptureImportPanel() {
  const [captures, setCaptures] = useState<CaptureRecord[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const refresh = useCallback(async () => {
    try {
      const res = await listCaptures(0, 50)
      setCaptures(res.items)
    } catch (e) {
      setError(String(e))
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  async function onFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    setLoading(true)
    setError('')
    try {
      await importCapture(file)
      await refresh()
    } catch (err) {
      setError(String(err))
    } finally {
      setLoading(false)
      e.target.value = '' // 允许重复上传同一文件
    }
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <h2 className="panel-title">抓包导入</h2>
        <span className="panel-subtitle">上传 pcap/pcapng 文件，解析后入库</span>
      </div>

      <div>
        <input
          type="file"
          accept=".pcap,.pcapng,.cap"
          onChange={onFileChange}
          disabled={loading}
        />
        {loading && <span className="info"> 上传解析中…</span>}
      </div>

      {error && <div className="error">{error}</div>}

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>名称</th>
              <th>格式</th>
              <th>包数</th>
              <th>大小</th>
              <th>链路类型</th>
              <th>导入时间</th>
            </tr>
          </thead>
          <tbody>
            {captures.length === 0 ? (
              <tr>
                <td colSpan={6} className="info">
                  暂无 capture，请上传文件
                </td>
              </tr>
            ) : (
              captures.map((c) => (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td>{c.format}</td>
                  <td>{c.packet_count}</td>
                  <td>{formatBytes(c.byte_size)}</td>
                  <td>{c.link_type}</td>
                  <td>{new Date(c.imported_at).toLocaleString()}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}
