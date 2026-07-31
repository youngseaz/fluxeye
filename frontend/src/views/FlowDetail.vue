<template>
  <div class="detail-page">
    <!-- 加载中 -->
    <el-skeleton :rows="8" animated v-if="loading" />

    <!-- 404 -->
    <el-empty description="未找到该流记录" v-else-if="!flow" />

    <!-- 详情 -->
    <template v-else>
      <el-page-header @back="goBack" content="流详情" style="margin-bottom: 16px" />

      <el-row :gutter="16">
        <!-- 基本信息 -->
        <el-col :span="12">
          <el-card shadow="hover">
            <template #header><span class="card-title">基本信息</span></template>
            <el-descriptions :column="2" border size="small">
              <el-descriptions-item label="流 ID">{{ flow.id }}</el-descriptions-item>
              <el-descriptions-item label="时间">{{ formatTime(flow.timestamp) }}</el-descriptions-item>
              <el-descriptions-item label="源 IP">{{ flow.src_ip }}</el-descriptions-item>
              <el-descriptions-item label="目标 IP">{{ flow.dst_ip }}</el-descriptions-item>
              <el-descriptions-item label="源端口">{{ flow.src_port }}</el-descriptions-item>
              <el-descriptions-item label="目标主机" v-if="flow.dst_host" :span="2">{{ flow.dst_host }}</el-descriptions-item>
              <el-descriptions-item label="抓包网卡" v-if="flow.interface" :span="2">{{ flow.interface }}</el-descriptions-item>
              <el-descriptions-item label="目标端口">{{ flow.dst_port }}</el-descriptions-item>
              <el-descriptions-item label="传输层">
                <el-tag size="small">{{ flow.l4_proto.toUpperCase() }}</el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="应用层">
                <el-tag :type="tagType" size="small">{{ flow.l7_proto.toUpperCase() }}</el-tag>
              </el-descriptions-item>
            </el-descriptions>
          </el-card>
        </el-col>

        <!-- 流量统计 -->
        <el-col :span="12">
          <el-card shadow="hover">
            <template #header><span class="card-title">流量统计</span></template>
            <el-descriptions :column="2" border size="small">
              <el-descriptions-item label="发送字节">{{ formatBytes(flow.bytes_sent) }}</el-descriptions-item>
              <el-descriptions-item label="接收字节">{{ formatBytes(flow.bytes_recv) }}</el-descriptions-item>
              <el-descriptions-item label="总流量">{{ formatBytes(flow.bytes_sent + flow.bytes_recv) }}</el-descriptions-item>
              <el-descriptions-item label="发送包数">{{ flow.packets_sent }}</el-descriptions-item>
              <el-descriptions-item label="接收包数">{{ flow.packets_recv }}</el-descriptions-item>
              <el-descriptions-item label="持续时间">{{ (flow.duration_ms / 1000).toFixed(2) }}s</el-descriptions-item>
            </el-descriptions>
          </el-card>
        </el-col>
      </el-row>

      <!-- 地理位置信息 -->
      <el-card shadow="hover" style="margin-top: 16px" v-if="flow.dst_asn || flow.dst_country">
        <template #header><span class="card-title">目标地理位置</span></template>
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item label="国家" v-if="flow.dst_country">
            <span :class="['fi', 'fi-' + flow.dst_country.toLowerCase(), 'geo-flag-icon']"></span>
            {{ countryName(flow.dst_country) }}
          </el-descriptions-item>
          <el-descriptions-item label="省/州" v-if="flow.dst_region">
            {{ flow.dst_region }}
          </el-descriptions-item>
          <el-descriptions-item label="城市" v-if="flow.dst_city">
            {{ flow.dst_city }}
          </el-descriptions-item>
          <el-descriptions-item label="ASN" v-if="flow.dst_asn">
            AS{{ flow.dst_asn }}
          </el-descriptions-item>
          <el-descriptions-item label="AS 组织" v-if="flow.dst_as_org">
            {{ flow.dst_as_org }}
          </el-descriptions-item>
          <el-descriptions-item label="经纬度" v-if="flow.dst_lat || flow.dst_lon">
            {{ flow.dst_lat?.toFixed(4) }}, {{ flow.dst_lon?.toFixed(4) }}
          </el-descriptions-item>
        </el-descriptions>
      </el-card>

      <!-- TLS 信息 -->
      <el-card shadow="hover" style="margin-top: 16px" v-if="isTLS">
        <template #header><span class="card-title">TLS 信息</span></template>
        <el-descriptions :column="1" border size="small">
          <el-descriptions-item label="协议">
            <el-tag type="success" size="small">TLS {{ flow.l7_proto.toUpperCase() }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="密钥可用">
            <el-tag :type="hasKey ? 'success' : 'warning'" size="small">
              {{ hasKey ? '✅ 有对应密钥（可用 Wireshark 解密）' : '❌ 无密钥' }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="目标端口" v-if="flow.dst_port === 443 || flow.dst_port === 8443">
            {{ flow.dst_port }} (HTTPS)
          </el-descriptions-item>
        </el-descriptions>
        <div style="font-size: 12px; color: #909399; margin-top: 8px">
          💡 设置 <code>SSLKEYLOGFILE</code> 环境变量启动浏览器/curl，
          FluxEye 自动捕获密钥并关联 TLS 流。
          导出的 pcap + keylog 可用 Wireshark 离线解密。
        </div>
      </el-card>

      <!-- 请求内容 -->
      <el-card shadow="hover" style="margin-top: 16px" v-if="flow.l7_meta">
        <template #header><span class="card-title">请求内容</span></template>
        <div class="request-content">{{ formatMeta(flow.l7_meta) }}</div>
      </el-card>

      <!-- 原始报文 (Wireshark 风格) -->
      <el-card shadow="hover" style="margin-top: 16px" v-if="hasPcap">
        <template #header>
          <div class="pcap-header">
            <span class="card-title">原始报文</span>
            <div class="pcap-header-actions">
              <el-tag size="small" type="info" v-if="pcapFile">pcap: {{ pcapFilename }}</el-tag>
              <el-button size="small" type="primary" :loading="loadingPackets" @click="loadPackets">
                {{ loadingPackets ? '加载中...' : '查看报文' }}
              </el-button>
            </div>
          </div>
        </template>

        <!-- 加载中 -->
        <el-skeleton :rows="4" animated v-if="loadingPackets" />

        <!-- 错误提示 -->
        <el-alert v-else-if="packetsError" :title="packetsError" type="warning" show-icon closable />

        <!-- 报文列表 -->
        <template v-else-if="packets.length > 0">
          <el-table :data="packets" stripe size="small" style="width:100%" max-height="500"
            @row-click="togglePacket" :row-class-name="packetRowClass">
            <el-table-column label="#" width="50" type="index" />
            <el-table-column label="时间" min-width="160">
              <template #default="{ row }">{{ formatTime(row.timestamp) }}</template>
            </el-table-column>
            <el-table-column label="方向" width="65">
              <template #default="{ row }">
                <span :class="row.summary.startsWith('←') ? 'dir-in' : 'dir-out'">
                  {{ row.summary.startsWith('←') ? '← 入' : '→ 出' }}
                </span>
              </template>
            </el-table-column>
            <el-table-column label="协议" width="60">
              <template #default="{ row }">
                {{ row.summary.includes('TCP') ? 'TCP' : row.summary.includes('UDP') ? 'UDP' : 'IP' }}
              </template>
            </el-table-column>
            <el-table-column label="长度" width="70">
              <template #default="{ row }">{{ row.length }} B</template>
            </el-table-column>
            <el-table-column label="摘要" min-width="220">
              <template #default="{ row }">{{ row.summary }}</template>
            </el-table-column>
            <el-table-column label="HEX" width="50">
              <template #default="{ row }">
                <el-link type="primary" size="small" @click.stop="togglePacket(row)">
                  {{ isSelected(row) ? '▾' : '▸' }}
                </el-link>
              </template>
            </el-table-column>
          </el-table>

          <!-- 选中包的 HEX 详情 (Wireshark 底部窗格风格) -->
          <transition name="hex-fade">
            <div v-if="selectedPacket" class="hex-pane">
              <div class="hex-pane-header">
                <span>原始报文 ({{ selectedPacket.length }} bytes)</span>
                <el-button size="small" @click="copyHex">复制 HEX</el-button>
              </div>
              <pre class="hex-dump"><code v-html="formatHexDump(selectedPacket.raw_hex)"></code></pre>
              <div class="hex-legend">
                <span class="legend-addr">偏移</span>
                <span class="legend-ascii">可见字符</span>
                <span class="legend-hex">十六进制</span>
              </div>
            </div>
          </transition>
        </template>

        <!-- 无数据 -->
        <el-empty v-else description="点击 「查看报文」 加载数据" :image-size="60" />
      </el-card>

      <!-- 流追踪 (Follow TCP/UDP/SCTP Stream) -->
      <el-card shadow="hover" style="margin-top: 16px" v-if="hasPcap && (flow?.l4_proto === 'tcp' || flow?.l4_proto === 'udp' || flow?.l4_proto === 'sctp')">
        <template #header>
          <div class="pcap-header">
            <span class="card-title">{{ {tcp:'TCP', udp:'UDP', sctp:'SCTP'}[flow?.l4_proto ?? ''] || flow?.l4_proto?.toUpperCase() }} 流追踪</span>
            <div class="pcap-header-actions">
              <el-radio-group v-model="streamView" size="small" style="margin-right:8px">
                <el-radio-button value="ascii">ASCII</el-radio-button>
                <el-radio-button value="hex">HEX</el-radio-button>
              </el-radio-group>
              <el-button size="small" type="primary" :loading="loadingStream" @click="loadStream">
                {{ loadingStream ? '加载中...' : 'Follow Stream' }}
              </el-button>
            </div>
          </div>
        </template>

        <el-skeleton :rows="4" animated v-if="loadingStream" />
        <el-alert v-else-if="streamError" :title="streamError" type="warning" show-icon closable />

        <template v-else-if="streamData.client_packets > 0 || streamData.server_packets > 0">
          <div style="margin-bottom:8px;font-size:12px;color:#909399">
            <el-tag size="small" type="success" style="margin-right:4px">{{ streamData.client_packets }} 个包</el-tag>
            <el-tag size="small" type="warning" style="margin-right:4px">{{ streamData.server_packets }} 个包</el-tag>
            <el-tag size="small" type="info">{{ (streamData.total_bytes / 1024).toFixed(1) }} KB</el-tag>
            <el-tag v-if="streamData.stream_closed" size="small" type="danger" style="margin-left:4px">已关闭</el-tag>
          </div>
          <pre class="stream-dump"><code v-html="formatStream()"></code></pre>
        </template>

        <el-empty v-else description="点击「Follow Stream」加载重组数据" :image-size="60" />
      </el-card>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { fetchFlowDetail } from '@/services/api'
import type { Conversation } from '@/types'
import { countryName } from '@/utils/country'
import axios from 'axios'

const route = useRoute()
const router = useRouter()
const flow = ref<Conversation | null>(null)
const loading = ref(true)

const tagType = computed(() => {
  const m: Record<string, string> = { http: '', tls: 'success', dns: 'warning', quic: 'danger' }
  return m[flow.value?.l7_proto ?? ''] || 'info'
})

const isTLS = computed(() => {
  return flow.value?.l7_proto?.toLowerCase() === 'tls'
})

const hasKey = computed(() => {
  return flow.value?.l7_meta?.includes('tls_key_available=true') ?? false
})

const hasPcap = computed(() => {
  return !!(flow.value as any)?.pcap_file
})

// ── 原始报文 ────────────────────────────────────────
const packets = ref<any[]>([])
const selectedPacket = ref<any>(null)
const loadingPackets = ref(false)
const packetsError = ref('')
const pcapFile = ref('')

const pcapFilename = computed(() => pcapFile.value ? pcapFile.value.split('/').pop() : '')

// ── TCP 流追踪 ──────────────────────────────────────
const streamView = ref('ascii')
const loadingStream = ref(false)
const streamError = ref('')
const streamData = ref<any>({
  client_packets: 0, server_packets: 0,
  client_data: '', server_data: '',
  total_bytes: 0, stream_closed: false,
})

async function loadPackets() {
  const id = flow.value?.id
  if (!id) return
  loadingPackets.value = true
  packetsError.value = ''
  packets.value = []
  selectedPacket.value = null
  try {
    const { data } = await axios.get(`/api/v1/traffic/flows/${id}/packets`)
    packets.value = data.packets || []
    pcapFile.value = data.pcap_file || ''
    if (packets.value.length === 0) {
      packetsError.value = '该流没有关联的 pcap 报文数据'
    }
  } catch (e: any) {
    packetsError.value = e?.response?.data?.detail || '获取报文失败'
  }
  loadingPackets.value = false
}

async function loadStream() {
  const id = flow.value?.id
  if (!id) return
  loadingStream.value = true
  streamError.value = ''
  streamData.value = { client_packets: 0, server_packets: 0, client_data: '', server_data: '', total_bytes: 0, stream_closed: false }
  try {
    const { data } = await axios.get(`/api/v1/traffic/flows/${id}/stream`)
    if (data.error) {
      streamError.value = data.error
    } else {
      streamData.value = data
    }
  } catch (e: any) {
    streamError.value = e?.response?.data?.detail || '获取 TCP 流失败'
  }
  loadingStream.value = false
}

function formatStream(): string {
  const view = streamView.value
  const cHex = streamData.value.client_data || ''
  const sHex = streamData.value.server_data || ''
  const cBytes = hexToBytes(cHex)
  const sBytes = hexToBytes(sHex)

  if (view === 'hex') {
    return formatStreamHex(cBytes, sBytes)
  }
  return formatStreamAscii(cBytes, sBytes)
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
  }
  return bytes
}

function formatStreamAscii(client: Uint8Array, server: Uint8Array): string {
  const maxLen = Math.max(client.length, server.length)
  const chunkSize = 64
  const lines: string[] = []
  let ci = 0, si = 0
  while (ci < client.length || si < server.length) {
    const cChunk = client.slice(ci, ci + chunkSize)
    const sChunk = server.slice(si, si + chunkSize)
    const cText = bytesToAscii(cChunk)
    const sText = bytesToAscii(sChunk)
    const lblC = `C▶ ${String(ci).padStart(6, '0')}`
    const lblS = `S◀ ${String(si).padStart(6, '0')}`
    if (cChunk.length > 0) {
      lines.push(`<span class="stream-c">${lblC}  ${cText}</span>`)
    }
    if (sChunk.length > 0) {
      lines.push(`<span class="stream-s">${lblS}  ${sText}</span>`)
    }
    ci += chunkSize
    si += chunkSize
  }
  return lines.join('\n')
}

function formatStreamHex(client: Uint8Array, server: Uint8Array): string {
  const maxLen = Math.max(client.length, server.length)
  const chunkSize = 16
  const lines: string[] = []
  let ci = 0, si = 0
  while (ci < client.length || si < server.length) {
    const cChunk = client.slice(ci, ci + chunkSize)
    const sChunk = server.slice(si, si + chunkSize)
    const cHex = bytesToHex(cChunk)
    const sHex = bytesToHex(sChunk)
    if (cChunk.length > 0) {
      lines.push(`<span class="stream-c">C▶${String(ci).padStart(6, '0')}  ${cHex}</span>`)
    }
    if (sChunk.length > 0) {
      lines.push(`<span class="stream-s">S◀${String(si).padStart(6, '0')}  ${sHex}</span>`)
    }
    ci += chunkSize
    si += chunkSize
  }
  return lines.join('\n')
}

function bytesToAscii(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b >= 32 && b <= 126 ? String.fromCharCode(b) : '.').join('')
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' ')
}

function togglePacket(row: any) {
  selectedPacket.value = isSelected(row) ? null : row
}

function isSelected(row: any) {
  return selectedPacket.value?.timestamp === row.timestamp &&
         selectedPacket.value?.length === row.length
}

function packetRowClass({ row }: { row: any }) {
  return isSelected(row) ? 'hex-row-selected' : ''
}

function formatTime(ts: number | string): string {
  if (!ts && ts !== 0) return '-'
  let ms: number
  if (typeof ts === 'number') {
    ms = ts * 1000
  } else if (ts.includes('T') || ts.includes('-')) {
    // ISO 8601 string
    const d = new Date(ts)
    return isNaN(d.getTime()) ? ts : formatDate(d)
  } else {
    ms = Number(ts) * 1000
  }
  const d = new Date(ms)
  return isNaN(d.getTime()) ? String(ts) : formatDate(d)
}

function formatDate(d: Date): string {
  return `${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}.${String(d.getMilliseconds()).padStart(3, '0')}`
}

function formatHexDump(hex: string): string {
  const lines: string[] = []
  for (let i = 0; i < hex.length; i += 64) {
    const addr = (i / 2).toString(16).padStart(8, '0')
    const hexBytes = hex.slice(i, i + 64)
    const hexPart = hexBytes.replace(/(.{2})/g, '$1 ').trim()
    const asciiPart = hexBytes.replace(/.{2}/g, (b) => {
      const c = parseInt(b, 16)
      return c >= 32 && c <= 126 ? String.fromCharCode(c) : '.'
    })
    lines.push(
      `<span class="addr-col">${addr}</span>  ` +
      `<span class="ascii-col">${asciiPart.padEnd(16)}</span>  ` +
      `<span class="hex-col">${hexPart.padEnd(48)}</span>`
    )
  }
  return lines.join('\n')
}

function copyHex() {
  if (!selectedPacket.value?.raw_hex) return
  navigator.clipboard.writeText(selectedPacket.value.raw_hex)
}

function formatBytes(b: number) {
  if (b >= 1_000_000) return `${(b / 1_000_000).toFixed(2)} MB`
  if (b >= 1_000) return `${(b / 1_000).toFixed(2)} KB`
  return `${b} B`
}

function goBack() {
  router.back()
}

function formatMeta(meta: string): string {
  if (meta.startsWith('tls_key_available=true')) return '🔐 TLS 密钥可用'
  return meta
}

onMounted(async () => {
  const id = Number(route.params.id)
  if (id) {
    flow.value = await fetchFlowDetail(id)
  }
  loading.value = false
})
</script>

<style scoped>
.detail-page {
  max-width: 1400px;
  margin: 0 auto;
}
.card-title {
  font-weight: 600;
}
.meta-content {
  background: #f5f7fa;
  padding: 12px;
  border-radius: 4px;
  font-size: 13px;
  line-height: 1.6;
  overflow-x: auto;
}
/* ── 原始报文卡片 ──────────────────────────────────── */
.pcap-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
}
.pcap-header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}
.dir-out { color: #409eff; font-weight: 600; }
.dir-in { color: #67c23a; font-weight: 600; }
/* HEX 详情窗格 */
.hex-pane {
  margin-top: 12px;
  border-top: 2px solid #409eff;
  padding-top: 8px;
}
.hex-pane-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 13px;
  font-weight: 600;
  margin-bottom: 8px;
}
.hex-dump {
  background: #1e1e1e; color: #d4d4d4; padding: 12px;
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
  font-size: 12px; line-height: 1.6; overflow-x: auto;
  border-radius: 4px; margin: 0; max-height: 320px; overflow-y: auto;
}
.hex-dump .ascii-col { color: #67c23a; }
.hex-dump .hex-col { color: #e6a23c; }
.hex-dump .addr-col { color: #909399; }
.hex-legend {
  display: flex; gap: 24px; margin-top: 6px; padding: 4px 12px;
  font-size: 11px; font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
  background: #252526; border-radius: 4px; color: #909399;
}
.hex-legend .legend-addr { color: #909399; }
.hex-legend .legend-ascii { color: #67c23a; margin-left: 55px; }
.hex-legend .legend-hex { color: #e6a23c; margin-left: 98px; }
/* 选中行高亮 */
:deep(.hex-row-selected) {
  background-color: #e6f7ff !important;
}
.hex-fade-enter-active, .hex-fade-leave-active {
  transition: opacity 0.25s ease;
}
.hex-fade-enter-from, .hex-fade-leave-to {
  opacity: 0;
}
/* TCP 流追踪 */
.stream-dump {
  background: #1e1e1e; color: #d4d4d4; padding: 12px;
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
  font-size: 12px; line-height: 1.5; overflow-x: auto;
  border-radius: 4px; margin: 0; max-height: 500px; overflow-y: auto;
  white-space: pre;
}
.stream-dump .stream-c { color: #409eff; display: block; }
.stream-dump .stream-s { color: #e6a23c; display: block; }
</style>
