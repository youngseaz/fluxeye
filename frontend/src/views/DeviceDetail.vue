<template>
  <div class="device-detail-page">
    <!-- 返回按钮 -->
    <el-button size="small" @click="$router.push('/profiles')" style="margin-bottom: 12px">
      ← 返回设备列表
    </el-button>

    <!-- 加载中 -->
    <el-skeleton :rows="8" animated v-if="loading" />

    <!-- 无数据 -->
    <el-empty v-else-if="notFound" description="该设备在选定时间范围内无流量数据" :image-size="80">
      <el-button size="small" @click="$router.push('/profiles')">← 返回设备列表</el-button>
    </el-empty>

    <!-- 设备数据 -->
    <template v-else-if="device.ip || device.mac">
      <!-- 设备概要 -->
      <el-card shadow="hover" :class="['summary-card', 'risk-' + device.risk_level]" style="margin-bottom: 16px">
        <div class="summary-header">
          <div>
            <div class="device-ip">{{ device.ip }} <span v-if="device.hostname" class="hostname">({{ device.hostname }})</span></div>
            <div class="device-mac" v-if="device.mac">
              {{ device.mac }}
              <el-tag v-if="device.vendor" size="small" type="info" effect="plain" style="margin-left: 6px">{{ device.vendor }}</el-tag>
            </div>
          </div>
          <el-tag v-if="device.risk_level" :type="riskTagType(device.risk_level)" size="large" effect="dark">
            {{ device.risk_level.toUpperCase() }} · {{ device.risk_score }}
          </el-tag>
        </div>
      </el-card>

      <!-- 统计卡片 -->
      <el-row :gutter="12" style="margin-bottom: 16px">
        <el-col :xs="12" :sm="6" v-for="stat in stats" :key="stat.label">
          <el-card shadow="never" class="stat-card">
            <div class="stat-label">{{ stat.label }}</div>
            <div class="stat-value">{{ stat.value }}</div>
          </el-card>
        </el-col>
      </el-row>

      <!-- 实时会话 + 详情 Tabs -->
      <el-card shadow="hover">
        <el-tabs v-model="activeTab">
          <el-tab-pane label="实时会话" name="sessions">
            <div class="toolbar">
              <el-radio-group v-model="sessionRange" size="small" @change="fetchSessions">
                <el-radio-button value="5m">最近 5 分钟</el-radio-button>
                <el-radio-button value="15m">15 分钟</el-radio-button>
                <el-radio-button value="1h">1 小时</el-radio-button>
              </el-radio-group>
            </div>
            <el-table :data="sessions" stripe size="small" style="width: 100%" max-height="500">
              <el-table-column prop="timestamp" label="时间" min-width="150">
                <template #default="{ row }">{{ formatTime(row.timestamp) }}</template>
              </el-table-column>
              <el-table-column label="方向" width="70">
                <template #default="{ row }">
                  <el-tag v-if="row.src_ip === queryIp" size="small" type="primary">→ 出</el-tag>
                  <el-tag v-else size="small" type="success">← 入</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="对端" min-width="160">
                <template #default="{ row }">
                  {{ row.src_ip === queryIp ? row.dst_ip : row.src_ip }}:{{ row.src_ip === queryIp ? row.dst_port : row.src_port }}
                </template>
              </el-table-column>
              <el-table-column prop="l7_proto" label="协议" width="90" />
              <el-table-column label="流量" width="100">
                <template #default="{ row }">{{ formatBytes(row.bytes_sent + row.bytes_recv) }}</template>
              </el-table-column>
              <el-table-column prop="duration_ms" label="时长" width="80">
                <template #default="{ row }">{{ (row.duration_ms / 1000).toFixed(1) }}s</template>
              </el-table-column>
              <el-table-column label="地区" width="90">
                <template #default="{ row }">
                  <span v-if="row.dst_country">{{ countryFlag(row.dst_country) }} {{ countryName(row.dst_country) }}</span>
                </template>
              </el-table-column>
              <el-table-column label="操作" width="60" fixed="right">
                <template #default="{ row }">
                  <el-link type="primary" size="small" @click="$router.push('/flows/' + row.id)">详情</el-link>
                </template>
              </el-table-column>
            </el-table>
            <el-empty v-if="sessions.length === 0" description="暂无会话数据" :image-size="60" />
          </el-tab-pane>

          <el-tab-pane label="协议分布" name="protocols">
            <div v-for="p in device.top_protocols" :key="p.protocol" class="detail-row">
              <span class="detail-name">{{ p.protocol }}</span>
              <span class="detail-bar-bg"><span class="detail-bar" :style="{ width: pct(p.bytes, totalBytes) + '%' }" /></span>
              <span class="detail-val">{{ formatBytes(p.bytes) }}</span>
            </div>
            <el-empty v-if="device.top_protocols.length === 0" description="暂无协议数据" :image-size="60" />
          </el-tab-pane>

          <el-tab-pane label="访问域名" name="domains">
            <div v-for="d in device.top_domains" :key="d.host" class="detail-row">
              <span class="detail-name" :title="d.host">{{ d.host }}</span>
              <span class="detail-bar-bg"><span class="detail-bar bar-green" :style="{ width: pct(d.bytes, totalBytes) + '%' }" /></span>
              <span class="detail-val">{{ formatBytes(d.bytes) }}</span>
            </div>
            <el-empty v-if="device.top_domains.length === 0" description="暂无域名数据" :image-size="60" />
          </el-tab-pane>

          <el-tab-pane label="通信对端" name="peers">
            <div v-for="p in device.top_peers" :key="p.ip" class="detail-row">
              <span class="detail-name">{{ p.ip }}</span>
              <el-tag size="small" :type="p.direction === 'egress' ? 'primary' : 'success'" style="margin:0 6px">
                {{ p.direction === 'egress' ? '→ 出' : '← 入' }}
              </el-tag>
              <span class="detail-bar-bg"><span class="detail-bar bar-orange" :style="{ width: pct(p.bytes_total, totalBytes) + '%' }" /></span>
              <span class="detail-val">{{ formatBytes(p.bytes_total) }}</span>
            </div>
            <el-empty v-if="device.top_peers.length === 0" description="暂无对端数据" :image-size="60" />
          </el-tab-pane>

          <el-tab-pane label="目标地区" name="countries">
            <div v-for="c in device.top_countries" :key="c.country" class="detail-row">
              <span class="detail-name">{{ countryFlag(c.country) }} {{ countryName(c.country) }}</span>
              <span class="detail-bar-bg"><span class="detail-bar bar-purple" :style="{ width: pct(c.bytes, totalBytes) + '%' }" /></span>
              <span class="detail-val">{{ formatBytes(c.bytes) }}</span>
            </div>
            <el-empty v-if="device.top_countries.length === 0" description="暂无地区数据" :image-size="60" />
          </el-tab-pane>
        </el-tabs>
      </el-card>
    </template>

    <el-empty v-else description="正在加载..." :image-size="80" />
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { useRoute } from 'vue-router'
import { fetchDeviceProfileDetail, fetchConversations } from '@/services/api'
import type { DeviceProfile, Conversation } from '@/types'
import { countryFlag, countryName } from '@/utils/country'

const route = useRoute()
const deviceIp = ref((route.params.ip as string) || '')
const loading = ref(false)
const activeTab = ref('sessions')
const sessionRange = ref('5m')

const device = reactive<DeviceProfile>({
  ip: '', mac: '', vendor: '', hostname: '',
  bytes_sent: 0, bytes_recv: 0, packets_sent: 0, packets_recv: 0,
  flow_count: 0, first_seen: null, last_seen: null, active_seconds: 0,
  top_protocols: [], top_services: [], top_domains: [], top_peers: [], top_countries: [],
  risk_score: 0, risk_events: 0, risk_level: '',
})

const sessions = ref<Conversation[]>([])
const notFound = ref(false)

// 用设备真实 IP（从后端返回的 device.ip）查询会话，避免 route param 是 MAC 地址
const queryIp = computed(() => device.ip || deviceIp.value)

const totalBytes = computed(() => device.bytes_sent + device.bytes_recv)

const stats = computed(() => [
  { label: '发送流量', value: formatBytes(device.bytes_sent) },
  { label: '接收流量', value: formatBytes(device.bytes_recv) },
  { label: '总包数', value: ((device.packets_sent + device.packets_recv)).toLocaleString() },
  { label: '总流数', value: device.flow_count.toLocaleString() },
  { label: '活跃时长', value: formatDuration(device.active_seconds) },
  { label: '风险事件', value: device.risk_events.toString() },
])

async function fetchDevice() {
  if (!deviceIp.value) return
  loading.value = true
  notFound.value = false
  try {
    const data = await fetchDeviceProfileDetail(deviceIp.value, '24h')
    if (data) {
      Object.assign(device, data)
      fetchSessions()
    } else {
      notFound.value = true
    }
  } catch (e: any) {
    notFound.value = true
    console.error('获取设备详情失败:', e)
  }
  loading.value = false
}

async function fetchSessions() {
  const ip = queryIp.value
  if (!ip) return
  try {
    const params = { page: 1, size: 50 } as any
    const [respOut, respIn] = await Promise.all([
      fetchConversations({ ...params, src_ip: ip }),
      fetchConversations({ ...params, dst_ip: ip }),
    ])
    const map = new Map<number, Conversation>()
    for (const f of [...(respOut.items || []), ...(respIn.items || [])]) {
      map.set(f.id, f)
    }
    sessions.value = Array.from(map.values()).slice(0, 100)
  } catch { sessions.value = [] }
}

function formatTime(s: string): string {
  const d = new Date(s)
  return `${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`
}

function formatBytes(b: number): string {
  if (b === 0) return '0 B'
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(b) / Math.log(1024))
  return (b / Math.pow(1024, i)).toFixed(i > 1 ? 1 : 0) + ' ' + u[i]
}

function formatDuration(sec: number): string {
  if (sec < 60) return sec + 's'
  if (sec < 3600) return Math.floor(sec / 60) + 'm ' + (sec % 60) + 's'
  return Math.floor(sec / 3600) + 'h ' + Math.floor((sec % 3600) / 60) + 'm'
}

function pct(val: number, total: number): number {
  return total > 0 ? +(val / total * 100).toFixed(1) : 0
}

function riskTagType(level: string): string {
  return { critical: 'danger', high: 'warning', medium: 'warning', low: 'info' }[level] || 'info'
}

watch(() => route.params.ip, (val) => {
  if (val) { deviceIp.value = val as string; fetchDevice() }
})

onMounted(fetchDevice)
</script>

<style scoped>
.device-detail-page { max-width: 1400px; margin: 0 auto; }
.summary-card.risk-critical { border-left: 4px solid #e61919; }
.summary-card.risk-high { border-left: 4px solid #ff8c00; }
.summary-card.risk-medium { border-left: 4px solid #f5c518; }
.summary-card.risk-low { border-left: 4px solid #52c41a; }

.summary-header { display: flex; justify-content: space-between; align-items: center; }
.device-ip { font-family: 'SF Mono', monospace; font-size: 18px; font-weight: 700; }
.device-ip .hostname { font-weight: 400; font-size: 14px; color: #909399; }
.device-mac { font-family: 'SF Mono', monospace; font-size: 12px; color: #909399; margin-top: 4px; }

.stat-card { text-align: center; }
.stat-card .stat-label { font-size: 12px; color: #909399; }
.stat-card .stat-value { font-size: 18px; font-weight: 700; margin-top: 4px; }

.toolbar { margin-bottom: 12px; }

.detail-row { display: flex; align-items: center; padding: 6px 0; gap: 8px; }
.detail-name { flex: 0 0 160px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px; }
.detail-bar-bg { flex: 1; height: 6px; background: #f0f0f0; border-radius: 3px; }
.detail-bar { display: block; height: 6px; background: #409eff; border-radius: 3px; transition: width 0.3s; }
.bar-green { background: #67c23a; }
.bar-orange { background: #e6a23c; }
.bar-purple { background: #9b59b6; }
.detail-val { flex: 0 0 80px; text-align: right; font-family: 'SF Mono', monospace; font-size: 12px; color: #606266; }
</style>
