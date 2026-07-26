<template>
  <el-card shadow="hover">
    <template #header>
      <div class="table-header">
        <span>实时会话</span>
        <div class="table-actions">
          <el-popover placement="bottom" :width="180" trigger="click">
            <template #reference>
              <el-button size="small" style="margin-right: 8px">列管理</el-button>
            </template>
            <div class="column-manager">
              <div
                v-for="col in columns"
                :key="col.key"
                class="column-item"
              >
                <el-checkbox
                  v-model="col.visible"
                  :label="col.label"
                  @change="saveColumnState"
                />
              </div>
            </div>
          </el-popover>
          <el-tag size="small" type="info">共 {{ totalCount }} 条</el-tag>
        </div>
      </div>
    </template>

    <!-- 过滤栏 -->
    <div v-if="showFilter" class="filter-bar">
      <el-form :inline="true" size="small">
        <el-form-item label="协议">
          <el-select v-model="filter.l7_proto" placeholder="全部" clearable style="width: 100px">
            <el-option label="HTTP" value="http" />
            <el-option label="TLS" value="tls" />
            <el-option label="DNS" value="dns" />
            <el-option label="QUIC" value="quic" />
            <el-option label="SSH" value="ssh" />
            <el-option label="SOCKS" value="socks" />
            <el-option label="NTP" value="ntp" />
          </el-select>
        </el-form-item>
        <el-form-item label="传输">
          <el-select v-model="filter.l4_proto" placeholder="全部" clearable style="width: 80px">
            <el-option label="TCP" value="tcp" />
            <el-option label="UDP" value="udp" />
          </el-select>
        </el-form-item>
        <el-form-item label="源 IP">
          <el-input v-model="filter.src_ip" placeholder="部分匹配" style="width: 130px" clearable />
        </el-form-item>
        <el-form-item label="目标 IP">
          <el-input v-model="filter.dst_ip" placeholder="部分匹配" style="width: 130px" clearable />
        </el-form-item>
        <el-form-item label="端口">
          <el-input v-model="filter.portStr" placeholder="如 80" style="width: 90px" clearable />
        </el-form-item>
        <el-form-item label="国家">
          <el-input v-model="filter.country" placeholder="US" style="width: 80px" clearable />
        </el-form-item>
        <el-form-item label="主机">
          <el-input v-model="filter.host" placeholder="部分匹配" style="width: 130px" clearable />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" size="small" @click="applyFilter">筛选</el-button>
          <el-button size="small" @click="resetFilter">重置</el-button>
        </el-form-item>
      </el-form>
    </div>

    <el-table
      :data="filteredItems"
      stripe
      size="small"
      style="width: 100%"
      @row-click="goDetail"
    >
      <template v-for="col in visibleColumns" :key="col.key">
        <el-table-column
          :prop="col.prop"
          :label="col.label"
          :width="col.width"
          :min-width="col.minWidth"
          :max-width="col.maxWidth"
        >
          <template #default="{ row }">
            <span v-if="col.key === 'geo'" v-html="renderCell(col.key, row)"></span>
            <span v-else>{{ renderCell(col.key, row) }}</span>
          </template>
        </el-table-column>
      </template>
    </el-table>

    <!-- 流详情对话框 -->
    <el-dialog v-model="detailVisible" title="流详情" width="600px" destroy-on-close>
      <template v-if="detailFlow">
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item label="源 IP" :span="2">
            {{ detailFlow.src_ip }}:{{ detailFlow.src_port }}
          </el-descriptions-item>
          <el-descriptions-item label="目标 IP" :span="2">
            {{ detailFlow.dst_ip }}:{{ detailFlow.dst_port }}
          </el-descriptions-item>
          <el-descriptions-item label="目标主机" v-if="detailFlow.dst_host" :span="2">
            {{ detailFlow.dst_host }}
          </el-descriptions-item>
          <el-descriptions-item label="抓包网卡" v-if="detailFlow.interface" :span="2">
            {{ detailFlow.interface }}
          </el-descriptions-item>
          <el-descriptions-item label="传输层">
            <el-tag size="small">{{ detailFlow.l4_proto?.toUpperCase() }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="应用层">
            <el-tag :type="protoTagType(detailFlow.l7_proto)" size="small">
              {{ detailFlow.l7_proto?.toUpperCase() }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="目标位置" v-if="detailFlow.dst_country" :span="2">
            <span :class="['fi', 'fi-' + detailFlow.dst_country.toLowerCase(), 'geo-flag-icon']"></span>
            {{ detailFlow.dst_country }}<span v-if="detailFlow.dst_region"> / {{ detailFlow.dst_region }}</span>
            <span v-if="detailFlow.dst_city"> / {{ detailFlow.dst_city }}</span>
            <span v-if="detailFlow.dst_asn" style="color:#909399;font-size:12px;margin-left:4px">AS{{ detailFlow.dst_asn }} {{ detailFlow.dst_as_org }}</span>
          </el-descriptions-item>
          <el-descriptions-item label="发送流量">{{ formatBytes(detailFlow.bytes_sent) }}</el-descriptions-item>
          <el-descriptions-item label="接收流量">{{ formatBytes(detailFlow.bytes_recv) }}</el-descriptions-item>
          <el-descriptions-item label="总流量">{{ formatBytes((detailFlow.bytes_sent || 0) + (detailFlow.bytes_recv || 0)) }}</el-descriptions-item>
          <el-descriptions-item label="发送包数">{{ detailFlow.packets_sent }}</el-descriptions-item>
          <el-descriptions-item label="接收包数">{{ detailFlow.packets_recv }}</el-descriptions-item>
          <el-descriptions-item label="持续时间">{{ ((detailFlow.duration_ms || 0) / 1000).toFixed(2) }}s</el-descriptions-item>
          <el-descriptions-item label="时间" :span="2">{{ detailFlow.timestamp }}</el-descriptions-item>
          <el-descriptions-item label="请求内容" :span="2" v-if="detailFlow.l7_meta">
            <div class="meta-content">{{ formatMeta(detailFlow.l7_meta) }}</div>
          </el-descriptions-item>
        </el-descriptions>
      </template>
    </el-dialog>
  </el-card>
</template>

<script setup lang="ts">
import { ref, computed, reactive } from 'vue'
import type { Page, Conversation } from '@/types'
import { useRouter } from 'vue-router'

const props = withDefaults(defineProps<{
  data: Conversation[] | Page | null
  showFilter?: boolean
}>(), {
  showFilter: false,
})

const router = useRouter()

// ── 列管理 ────────────────────────────────────────────

interface ColumnDef {
  key: string
  label: string
  visible: boolean
}

const STORAGE_KEY = 'fluxeye_livetable_columns'

function loadColumnState(): ColumnDef[] {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved) return JSON.parse(saved)
  } catch { /* ignore */ }
  return [
    { key: 'time', label: '时间', visible: true },
    { key: 'interface', label: '网卡', visible: true },
    { key: 'src', label: '源', visible: true },
    { key: 'dst', label: '目标', visible: true },
    { key: 'host', label: '目标主机', visible: true },
    { key: 'geo', label: '目标位置', visible: true },
    { key: 'proto', label: '协议', visible: true },
    { key: 'category', label: '类型', visible: true },
    { key: 'traffic', label: '流量', visible: true },
    { key: 'duration', label: '时长', visible: true },
    { key: 'first_seen', label: '首次活动', visible: false },
    { key: 'last_seen', label: '最后活动', visible: false },
  ]
}

const columns = ref<ColumnDef[]>(loadColumnState())

interface ColumnConfig {
  key: string
  prop?: string
  label: string
  width?: number | string
  minWidth?: number | string
  maxWidth?: number | string
}

const visibleColumns = computed<ColumnConfig[]>(() => {
  const colMap: Record<string, ColumnConfig> = {
    time:     { key: 'time', prop: 'timestamp', label: '时间', width: 170 },
    interface:{ key: 'interface', label: '网卡', width: 70 },
    src:      { key: 'src', label: '源', width: 165 },
    dst:      { key: 'dst', label: '目标', width: 165 },
    host:     { key: 'host', label: '目标主机', minWidth: 140, maxWidth: 260 },
    geo:      { key: 'geo', label: '目标位置', minWidth: 140, maxWidth: 240 },
    proto:    { key: 'proto', prop: 'l7_proto', label: '协议', width: 100 },
    category: { key: 'category', prop: 'l7_category', label: '类型', width: 80 },
    traffic:  { key: 'traffic', label: '流量', width: 95 },
    duration: { key: 'duration', label: '时长', width: 75 },
    first_seen:{ key: 'first_seen', label: '首次活动', width: 170 },
    last_seen: { key: 'last_seen', label: '最后活动', width: 170 },
  }
  return columns.value.filter(c => c.visible).map(c => colMap[c.key]).filter(Boolean)
})

function renderCell(key: string, row: any): string {
  switch (key) {
    case 'time': return formatTime(row.timestamp)
    case 'interface': return row.interface || '-'
    case 'src': return `${row.src_ip}:${row.src_port}`
    case 'dst': return `${row.dst_ip}:${row.dst_port}`
    case 'host': return row.dst_host || '-'
    case 'geo': return renderGeo(row)
    case 'proto': return `${(row.l4_proto || '').toUpperCase()}/${(row.l7_proto || 'UNKNOWN').toUpperCase()}`
    case 'category': return row.l7_category || '-'
    case 'traffic': return formatBytes((row.bytes_sent || 0) + (row.bytes_recv || 0))
    case 'duration': return `${((row.duration_ms || 0) / 1000).toFixed(1)}s`
    case 'first_seen': return formatTime(row.first_seen || row.timestamp)
    case 'last_seen': return formatTime(row.last_seen || row.timestamp)
    default: return ''
  }
}

function renderGeo(row: any): string {
  if (!row.dst_country) return '-'
  const flag = row.dst_country.toLowerCase()
  let html = `<span class="fi fi-${flag}"></span> ${row.dst_country}`
  if (row.dst_region) html += ` / ${row.dst_region}`
  if (row.dst_city) html += ` / ${row.dst_city}`
  return html
}

function saveColumnState() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(columns.value))
}

// 过滤状态
const filter = reactive({
  l7_proto: '',
  l4_proto: '',
  src_ip: '',
  dst_ip: '',
  portStr: '',
  country: '',
  host: '',
})

const tableItems = computed(() => {
  if (!props.data) return []
  if (Array.isArray(props.data)) return props.data
  return props.data?.items ?? []
})

const filteredItems = computed(() => {
  let items = tableItems.value
  if (filter.l7_proto) {
    items = items.filter((f) => f.l7_proto?.toLowerCase() === filter.l7_proto.toLowerCase())
  }
  if (filter.l4_proto) {
    items = items.filter((f) => f.l4_proto?.toLowerCase() === filter.l4_proto.toLowerCase())
  }
  if (filter.src_ip) {
    items = items.filter((f) => f.src_ip?.includes(filter.src_ip))
  }
  if (filter.dst_ip) {
    items = items.filter((f) => f.dst_ip?.includes(filter.dst_ip))
  }
  if (filter.portStr) {
    const p = parseInt(filter.portStr, 10)
    if (!isNaN(p)) {
      items = items.filter((f) => f.src_port === p || f.dst_port === p)
    }
  }
  if (filter.country) {
    items = items.filter((f) => f.dst_country?.toUpperCase() === filter.country.toUpperCase())
  }
  if (filter.host) {
    items = items.filter((f) => f.dst_host?.toLowerCase().includes(filter.host.toLowerCase()))
  }
  return items
})

const totalCount = computed(() => {
  if (!props.data) return 0
  if (Array.isArray(props.data)) return filteredItems.value.length
  return props.data?.total ?? 0
})

// 流详情对话框
const detailVisible = ref(false)
const detailFlow = ref<Conversation | null>(null)

function goDetail(row: any) {
  // 内存中的实时流 → 弹窗显示详情
  if (row && (row.id === 0 || row.id === undefined)) {
    detailFlow.value = row as Conversation
    detailVisible.value = true
    return
  }
  // 数据库中的历史流 → 跳转详情页
  router.push(`/flows/${row.id}`)
}

function applyFilter() {
  // computed 自动响应
}

function resetFilter() {
  filter.l7_proto = ''
  filter.l4_proto = ''
  filter.src_ip = ''
  filter.dst_ip = ''
  filter.portStr = ''
  filter.country = ''
  filter.host = ''
}

function formatTime(ts: string): string {
  const d = new Date(ts)
  const pad = (n: number) => String(n).padStart(2, '0')
  const sec = d.getSeconds() + d.getMilliseconds() / 1000
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${sec.toFixed(1)}`
}

function formatBytes(bytes: number): string {
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`
  return `${bytes} B`
}

function protoTagType(proto: string): string {
  const map: Record<string, string> = {
    http: '', tls: 'success', dns: 'warning',
    quic: 'danger', ssh: 'info',
  }
  return map[proto] || 'info'
}

function formatMeta(meta: string): string {
  if (meta.startsWith('tls_key_available=true')) return '🔐 TLS 密钥可用'
  // 完整报文用 --- 分隔，保留原格式
  return meta
}

</script>

<style scoped>
.table-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-weight: 600;
}
.table-actions {
  display: flex;
  gap: 8px;
}
.cell-ip {
  font-family: 'Courier New', monospace;
  font-size: 12px;
}
.cell-port {
  color: #909399;
  font-size: 11px;
}
.geo-cell {
  font-size: 12px;
  line-height: 1.4;
  display: inline-flex;
  align-items: center;
  gap: 3px;
  flex-wrap: wrap;
}
.geo-cell .fi {
  display: inline-block;
  line-height: 1;
  vertical-align: middle;
}
.geo-flag {
  font-weight: 600;
  line-height: 1;
}
.geo-region {
  color: #606266;
  line-height: 1;
}
.geo-city {
  color: #909399;
  font-size: 11px;
  line-height: 1;
}
.geo-empty {
  color: #c0c4cc;
}
.filter-bar {
  padding: 0 0 8px 0;
  border-bottom: 1px solid #ebeef5;
  margin-bottom: 8px;
}
.filter-bar :deep(.el-form-item) {
  margin-bottom: 0;
}
.meta-content {
  font-family: 'Courier New', monospace;
  font-size: 13px;
  padding: 8px 12px;
  background: #f5f7fa;
  border-radius: 4px;
  white-space: pre-wrap;
  word-break: break-all;
  line-height: 1.5;
}
.column-manager {
  padding: 4px 0;
}
.column-item {
  padding: 6px 8px;
  border-radius: 4px;
  transition: background 0.2s;
}
.column-item:hover {
  background: #f0f5ff;
}
.proto-tag {
  font-weight: 500;
  color: #303133;
}
</style>
