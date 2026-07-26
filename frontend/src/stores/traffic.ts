/** Pinia 流量数据 Store — 管理所有从 API 获取的流量数据 */

import { defineStore } from 'pinia'
import { ref } from 'vue'
import type {
  TrafficOverview,
  ProtocolDistribution,
  TopTalkersResponse,
  TimeSeriesResponse,
  Page,
  Conversation,
  ConversationFilters,
} from '@/types'
import {
  fetchOverview,
  fetchProtocols,
  fetchTopTalkers,
  fetchTimeSeries,
  fetchConversations,
} from '@/services/api'
import axios from 'axios'

export const useTrafficStore = defineStore('traffic', () => {
  // ── 状态 ─────────────────────────────────────────
  const overview = ref<TrafficOverview | null>(null)
  const protocols = ref<ProtocolDistribution | null>(null)
  const topTalkers = ref<TopTalkersResponse | null>(null)
  const timeSeries = ref<TimeSeriesResponse | null>(null)
  const conversations = ref<Page | null>(null)
  const liveSessions = ref<Conversation[]>([])
  const loading = ref(false)
  const error = ref<string | null>(null)

  // ── 时间范围 ─────────────────────────────────────
  const timeRange = ref('5m')

  // ── 操作 ─────────────────────────────────────────

  async function refreshAll() {
    loading.value = true
    error.value = null
    try {
      const [ov, pr, tt, ts] = await Promise.all([
        fetchOverview(timeRange.value),
        fetchProtocols(timeRange.value),
        fetchTopTalkers(20, timeRange.value),
        fetchTimeSeries('10s', timeRange.value),
      ])
      overview.value = ov
      protocols.value = pr
      topTalkers.value = tt
      timeSeries.value = ts
    } catch (e: any) {
      error.value = e?.message || '数据加载失败'
    } finally {
      loading.value = false
    }
  }

  async function refreshOverview() {
    try {
      overview.value = await fetchOverview(timeRange.value)
    } catch {
      // 静默失败，保留旧数据
    }
  }

  async function refreshConversations(filters: ConversationFilters = {}) {
    try {
      conversations.value = await fetchConversations(filters)
    } catch {
      // 静默失败
    }
  }

  async function refreshLiveSessions() {
    try {
      const { data } = await axios.get<Conversation[]>('/api/v1/traffic/live')
      liveSessions.value = data
    } catch {
      // 静默失败
    }
  }

  function setTimeRange(range: string) {
    timeRange.value = range
  }

  return {
    overview,
    protocols,
    topTalkers,
    timeSeries,
    conversations,
    liveSessions,
    loading,
    error,
    timeRange,
    refreshAll,
    refreshOverview,
    refreshConversations,
    refreshLiveSessions,
    setTimeRange,
  }
})
