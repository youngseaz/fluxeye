/** HTTP API 客户端 — 基于 axios，自动代理到后端 */

import axios from 'axios'
import type {
  AppStat,
  Conversation,
  DeviceProfile,
  DeviceProfileList,
  DnsClientStat,
  DnsDomainStat,
  DnsOverview,
  DnsTimePoint,
  DomainStat,
  GeoConfigInfo,
  GeoUpdateStatus,
  Page,
  ProtocolDistribution,
  SecurityEvent,
  SecurityOverview,
  ServiceStat,
  SystemStatus,
  TimeSeriesResponse,
  TopTalkersResponse,
  TrafficOverview,
  TrafficTotal,
} from '@/types'

const http = axios.create({
  baseURL: '/api/v1',
  timeout: 10000,
})

// ── 系统 ─────────────────────────────────────────────

export async function fetchSystemStatus(): Promise<SystemStatus> {
  const { data } = await http.get('/system/status')
  return data
}

// ── 概览 ─────────────────────────────────────────────

export async function fetchOverview(timeRange = '5m'): Promise<TrafficOverview> {
  const { data } = await http.get('/traffic/overview', { params: { time_range: timeRange } })
  return data
}

// ── 协议分布 ─────────────────────────────────────────

export async function fetchProtocols(timeRange = '1h', top = 10): Promise<ProtocolDistribution> {
  const { data } = await http.get('/traffic/protocols', {
    params: { time_range: timeRange, top },
  })
  return data
}

// ── Top Talkers ──────────────────────────────────────

export async function fetchTopTalkers(top = 20, timeRange = '30m'): Promise<TopTalkersResponse> {
  const { data } = await http.get('/traffic/top-talkers', {
    params: { top, time_range: timeRange },
  })
  return data
}

// ── 时序数据 ─────────────────────────────────────────

export async function fetchTimeSeries(interval = '10s', timeRange = '1h'): Promise<TimeSeriesResponse> {
  const { data } = await http.get('/traffic/time-series', {
    params: { interval, time_range: timeRange },
  })
  return data
}

// ── 会话列表 ─────────────────────────────────────────

import type { ConversationFilters } from '@/types'

export async function fetchConversations(filters: ConversationFilters = {}): Promise<Page> {
  const { data } = await http.get('/traffic/conversations', { params: filters })
  return data
}

// ── 流详情 ───────────────────────────────────────────

export async function fetchFlowDetail(id: number): Promise<Conversation | null> {
  try {
    const { data } = await http.get(`/traffic/flows/${id}`)
    return data
  } catch {
    return null
  }
}

// ── 安全态势 ─────────────────────────────────────────

export async function fetchSecurityOverview(timeRange = '1h'): Promise<SecurityOverview> {
  const { data } = await http.get('/security/overview', { params: { time_range: timeRange } })
  return data
}

export async function fetchSecurityEvents(
  timeRange = '1h',
  minScore = 0,
  severity = '',
  limit = 100,
): Promise<SecurityEvent[]> {
  const { data } = await http.get('/security/events', {
    params: { time_range: timeRange, min_score: minScore, severity, limit },
  })
  return data
}

// ── 域名统计 ─────────────────────────────────────────

export async function fetchTopDomains(timeRange = '1h', limit = 20): Promise<DomainStat[]> {
  const { data } = await http.get('/traffic/top-domains', {
    params: { time_range: timeRange, limit },
  })
  return data
}

// ── 应用统计 ─────────────────────────────────────────

export async function fetchAppStats(timeRange = '1h', limit = 20): Promise<AppStat[]> {
  const { data } = await http.get('/traffic/app-stats', {
    params: { time_range: timeRange, limit },
  })
  return data
}

// ── 流量总和统计 ─────────────────────────────────────

export async function fetchTrafficTotals(timeRange = '5m'): Promise<TrafficTotal> {
  const { data } = await http.get('/traffic/totals', {
    params: { time_range: timeRange },
  })
  return data
}

// ── 应用服务统计 ─────────────────────────────────────

export async function fetchServicesStats(timeRange = '1h', limit = 20): Promise<ServiceStat[]> {
  const { data } = await http.get('/traffic/services', {
    params: { time_range: timeRange, limit },
  })
  return data
}

// ── DNS 统计 ─────────────────────────────────────────

export async function fetchDnsOverview(timeRange = '1h'): Promise<DnsOverview> {
  const { data } = await http.get('/traffic/dns/overview', {
    params: { time_range: timeRange },
  })
  return data
}

export async function fetchDnsTopDomains(timeRange = '1h', limit = 20): Promise<DnsDomainStat[]> {
  const { data } = await http.get('/traffic/dns/top-domains', {
    params: { time_range: timeRange, limit },
  })
  return data
}

export async function fetchDnsTopClients(timeRange = '1h', limit = 20): Promise<DnsClientStat[]> {
  const { data } = await http.get('/traffic/dns/top-clients', {
    params: { time_range: timeRange, limit },
  })
  return data
}

export async function fetchDnsTimeseries(interval = '60s', timeRange = '1h'): Promise<DnsTimePoint[]> {
  const { data } = await http.get('/traffic/dns/timeseries', {
    params: { interval, time_range: timeRange },
  })
  return data
}

// ── 设备画像 ─────────────────────────────────────────

export async function fetchDeviceProfiles(
  timeRange = '1h',
  page = 1,
  size = 20,
  sortBy = 'bytes',
): Promise<DeviceProfileList> {
  const { data } = await http.get('/traffic/profiles', {
    params: { time_range: timeRange, page, size, sort_by: sortBy },
  })
  return data
}

export async function fetchDeviceProfileDetail(
  ip: string,
  timeRange = '1h',
): Promise<DeviceProfile | null> {
  const { data } = await http.get(`/traffic/profiles/${ip}`, {
    params: { time_range: timeRange },
  })
  return data
}

// ── GeoIP ─────────────────────────────────────────────

export async function fetchGeoConfig(): Promise<GeoConfigInfo> {
  const { data } = await http.get('/geo/config')
  return data
}

export async function updateGeoConfig(accountId: string, licenseKey: string): Promise<{ message: string }> {
  const { data } = await http.post('/geo/config', { account_id: accountId, license_key: licenseKey })
  return data
}

export async function fetchGeoDatabases(): Promise<{ files: any[]; dir: string }> {
  const { data } = await http.get('/geo/databases')
  return data
}

export async function uploadGeoDatabase(file: File): Promise<{ message: string; success: boolean }> {
  const form = new FormData()
  form.append('file', file)
  const { data } = await http.post('/geo/databases/upload', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data
}

export async function deleteGeoDatabase(filename: string): Promise<{ message: string; success: boolean }> {
  const { data } = await http.delete(`/geo/databases/${encodeURIComponent(filename)}`)
  return data
}

export async function triggerGeoUpdate(): Promise<{ message: string; success: boolean }> {
  const { data } = await http.post('/geo/update')
  return data
}
