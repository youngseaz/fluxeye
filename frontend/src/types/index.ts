/** FluxEye 前端类型定义 — 与后端 API 响应结构对齐 */

// ── 流记录 ──────────────────────────────────────────
export interface FlowRecord {
  timestamp: string
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  l4_proto: string
  l7_proto: string
  bytes_sent: number
  bytes_recv: number
  packets_sent: number
  packets_recv: number
  l7_meta: string
  l7_category: string
  duration_ms: number
  // 抓包网卡
  interface: string
  // 首次与最后活动时间
  first_seen: string
  last_seen: string
  // GeoIP + 主机
  dst_host: string
  dst_country: string
  dst_region: string
  dst_city: string
  dst_asn: number
  dst_as_org: string
  dst_lat: number
  dst_lon: number
}

// ── 概览 ────────────────────────────────────────────
export interface TrafficOverview {
  total_bps: number
  total_pps: number
  active_flows: number
  total_connections: number
  time_range: string
}

// ── 协议分布 ────────────────────────────────────────
export interface ProtocolStat {
  l7_proto: string
  bytes_total: number
  flow_count: number
  percentage: number
}

export interface ProtocolDistribution {
  time_range: string
  protocols: ProtocolStat[]
}

// ── Top Talkers ─────────────────────────────────────
export interface Talker {
  ip: string
  bytes_total: number
  direction: 'ingress' | 'egress'
}

export interface TopTalkersResponse {
  time_range: string
  top: number
  talkers: Talker[]
}

// ── 时序数据 ────────────────────────────────────────
export interface TimePoint {
  timestamp: string
  bps: number
  pps: number
}

export interface TimeSeriesResponse {
  interval: string
  time_range: string
  data: TimePoint[]
}

// ── 会话 ────────────────────────────────────────────
export interface Conversation {
  id: number
  timestamp: string
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  l4_proto: string
  l7_proto: string
  bytes_sent: number
  bytes_recv: number
  packets_sent: number
  packets_recv: number
  duration_ms: number
  l7_meta: string
  total_bytes: number
  // GeoIP 字段
  dst_country?: string
  dst_region?: string
  dst_city?: string
  dst_asn?: number
  dst_as_org?: string
  dst_lat?: number
  dst_lon?: number
}

export interface ConversationFilters {
  page?: number
  size?: number
  l7_proto?: string
  src_ip?: string
  dst_ip?: string
  time_start?: string
  time_end?: string
}

export interface Page {
  items: Conversation[]
  total: number
  page: number
  size: number
  pages: number
}

// ── 系统状态 ────────────────────────────────────────
export interface SystemStatus {
  status: string
  uptime_seconds: number
  storage_backend: string
  collector_running: boolean
  flows_cached: number
  version: string
}

// ── 安全态势 ────────────────────────────────────────
export interface RiskDetail {
  id: number
  name: string
  severity: number
  severity_name: string
  info: string
}

export interface SecurityEvent {
  timestamp: string
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  l4_proto: string
  l7_proto: string
  risks: RiskDetail[]
  risk_score: number
  risk_level: string
  bytes_total: number
  packets_total: number
  interface: string
  dst_host: string
  dst_country: string
  dst_city: string
}

export interface SecurityOverview {
  total_events: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  top_risks: { name: string; count: number }[]
  by_severity: { severity: string; count: number }[]
  time_range: string
}

// ── 域名统计 ────────────────────────────────────────
export interface DomainStat {
  host: string
  bytes_total: number
  flow_count: number
  percentage: number
}

// ── 应用统计 ────────────────────────────────────────
export interface AppStat {
  protocol: string
  bytes_total: number
  flow_count: number
  percentage: number
}

// ── 设备画像 ────────────────────────────────────
export interface PeerStat {
  ip: string
  bytes_total: number
  flow_count: number
  direction: string
}

export interface DeviceProfile {
  mac: string
  ip: string
  vendor: string
  hostname: string
  bytes_sent: number
  bytes_recv: number
  packets_sent: number
  packets_recv: number
  flow_count: number
  first_seen: string | null
  last_seen: string | null
  active_seconds: number
  top_protocols: { protocol: string; bytes: number; count: number }[]
  top_services: { service: string; bytes: number; count: number }[]
  top_domains: { host: string; bytes: number; count: number }[]
  top_peers: PeerStat[]
  top_countries: { country: string; bytes: number; count: number }[]
  risk_score: number
  risk_events: number
  risk_level: string
}

export interface DeviceProfileList {
  devices: DeviceProfile[]
  total: number
  page: number
  size: number
}

// ── GeoIP ──────────────────────────────────────────
export interface GeoDBFileInfo {
  edition: string
  path: string
  exists: boolean
  size_bytes: number
  age_days: number
  last_modified: string
}

export interface GeoUpdateStatus {
  available: boolean
  auto_update: boolean
  update_interval_days: number
  files: GeoDBFileInfo[]
  last_update_time: string
  updating: boolean
}

export interface GeoConfigInfo {
  account_id: string
  license_key: string
  has_account: boolean
  db_dir: string
  db_files: { name: string; size_bytes: number; modified: string }[]
}

// ── 应用服务统计 ────────────────────────────────────
export interface ServiceStat {
  total_bytes: number
  total_packets: number
  total_flows: number
  by_protocol: { protocol: string; bytes: number }[]
  by_category: { category: string; bytes: number }[]
  time_range: string
}
