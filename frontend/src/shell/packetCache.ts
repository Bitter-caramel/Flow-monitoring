/**
 * 包详情浏览器缓存（模块级、有界、带 TTL）。
 *
 * 目标：用户在包列表里逐包浏览、或从告警反复打开同一个包时，
 * 不必每次都打后端。缓存只在「真的点开过」之后写入，绝不预取。
 *
 * 策略（任务 16-7）：
 *   - key = `${captureId}:${no}`；
 *   - TTL = 5 分钟：读取时过期即删，视为未命中；
 *   - 容量上限 200 条：写入后若超限，淘汰最早写入的一条（Map 迭代顺序）。
 */

import type { PacketRecord } from '../api'

/** 缓存有效期：5 分钟。 */
export const PACKET_CACHE_TTL_MS = 5 * 60 * 1000

/** 缓存容量上限：200 条。 */
export const PACKET_CACHE_CAPACITY = 200

interface CachedPacket {
  rec: PacketRecord
  /** 写入时间（毫秒时间戳），用于 TTL 与淘汰。 */
  at: number
}

/** 模块级缓存：页面生命周期内复用，刷新即清空。 */
const cache = new Map<string, CachedPacket>()

/** 缓存键：证据包 + 包号。 */
export function packetCacheKey(captureId: string, no: number): string {
  return `${captureId}:${no}`
}

/**
 * 读缓存。
 *
 * 命中且未过期返回记录；未命中/已过期返回 null（过期的顺手删除）。
 * 空 captureId / 非正包号一律视为未命中，避免脏 key。
 */
export function readCachedPacket(
  captureId: string,
  no: number,
  now = Date.now(),
): PacketRecord | null {
  if (!captureId || !Number.isFinite(no) || no <= 0) return null
  const key = packetCacheKey(captureId, no)
  const hit = cache.get(key)
  if (!hit) return null
  if (now - hit.at > PACKET_CACHE_TTL_MS) {
    cache.delete(key)
    return null
  }
  return hit.rec
}

/**
 * 写缓存。
 *
 * 同一 key 重写时先删再插，保证 Map 的迭代顺序始终等于写入顺序；
 * 超出容量上限时从队首淘汰最旧写入，绝不无限增长。
 */
export function writeCachedPacket(
  captureId: string,
  no: number,
  rec: PacketRecord,
  now = Date.now(),
): void {
  if (!captureId || !Number.isFinite(no) || no <= 0) return
  const key = packetCacheKey(captureId, no)
  cache.delete(key)
  cache.set(key, { rec, at: now })
  while (cache.size > PACKET_CACHE_CAPACITY) {
    const oldest = cache.keys().next()
    if (oldest.done) break
    cache.delete(oldest.value)
  }
}
