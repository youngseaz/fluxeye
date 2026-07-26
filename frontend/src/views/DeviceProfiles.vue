<template>
  <div class="profiles-page">
    <!-- 标题栏 -->
    <el-row :gutter="16" style="margin-bottom: 16px" align="middle">
      <el-col :span="12">
        <div class="section-title">
          设备流量画像
          <el-tag size="small" type="info" style="margin-left: 8px">
            共 {{ list.total }} 台设备
          </el-tag>
        </div>
      </el-col>
      <el-col :span="12" style="text-align: right">
        <el-radio-group v-model="timeRange" size="small" @change="fetchData">
          <el-radio-button value="5m">5分钟</el-radio-button>
          <el-radio-button value="15m">15分钟</el-radio-button>
          <el-radio-button value="1h">1小时</el-radio-button>
          <el-radio-button value="6h">6小时</el-radio-button>
          <el-radio-button value="24h">24小时</el-radio-button>
        </el-radio-group>
        <el-select v-model="sortBy" size="small" style="width: 110px; margin-left: 8px" @change="fetchData">
          <el-option label="按流量" value="bytes" />
          <el-option label="按流数" value="flows" />
          <el-option label="按风险" value="risk" />
          <el-option label="按时间" value="last_seen" />
        </el-select>
      </el-col>
    </el-row>

    <!-- 加载/错误 -->
    <el-skeleton :rows="5" animated v-if="loading" />
    <el-alert v-if="error" :title="error" type="error" show-icon closable style="margin-bottom: 16px" @close="error = ''" />

    <!-- 设备卡片网格 -->
    <el-row :gutter="16" v-if="list.devices.length > 0">
      <el-col v-for="dev in list.devices" :key="dev.ip" :xs="24" :sm="12" :md="8" :lg="6" style="margin-bottom: 16px">
        <el-card shadow="hover" :class="['device-card', 'risk-' + dev.risk_level]" @click="selectDevice(dev)">
          <div class="device-header">
            <div class="device-ip">{{ dev.ip }}</div>
            <el-tag v-if="dev.risk_level" :type="riskTagType(dev.risk_level)" size="small" effect="dark">
              {{ dev.risk_level.toUpperCase() }}
            </el-tag>
          </div>
          <div class="device-mac-row" v-if="dev.mac">
            <span class="mac-label">{{ dev.mac }}</span>
            <el-tag v-if="dev.vendor" size="small" type="info" effect="plain">{{ dev.vendor }}</el-tag>
          </div>
          <div class="device-stats">
            <div class="stat-row">
              <span class="stat-label">发送</span>
              <span class="stat-val">{{ formatBytes(dev.bytes_sent) }}</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">接收</span>
              <span class="stat-val">{{ formatBytes(dev.bytes_recv) }}</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">流数</span>
              <span class="stat-val">{{ dev.flow_count }}</span>
            </div>
            <div class="stat-row" v-if="dev.last_seen">
              <span class="stat-label">最后活动</span>
              <span class="stat-val">{{ formatTime(dev.last_seen) }}</span>
            </div>
          </div>
          <!-- 访问的应用服务 -->
          <div class="device-services" v-if="dev.top_services && dev.top_services.length > 0">
            <div class="services-label">访问应用</div>
            <div class="services-tags">
              <el-tag
                v-for="svc in dev.top_services.slice(0, 4)"
                :key="svc.service"
                size="small"
                type=""
                effect="plain"
                class="service-tag"
              >{{ svc.service }}</el-tag>
              <el-tag v-if="dev.top_services.length > 4" size="small" type="info" effect="plain">
                +{{ dev.top_services.length - 4 }}
              </el-tag>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 空状态 -->
    <el-empty v-if="!loading && list.devices.length === 0" description="暂无设备数据" />

    <!-- 分页 -->
    <el-pagination
      v-if="list.total > list.size"
      v-model:current-page="page"
      :page-size="list.size"
      :total="list.total"
      layout="prev, pager, next"
      style="margin-top: 16px; justify-content: center"
      @current-change="fetchData"
    />

    <!-- 设备详情对话框 -->
    <el-dialog v-model="detailVisible" :title="dialogTitle" width="700px" destroy-on-close>
      <template v-if="detail.ip || detail.mac">
        <el-descriptions :column="2" border size="small" style="margin-bottom: 16px">
          <el-descriptions-item label="MAC 地址" v-if="detail.mac">{{ detail.mac }}</el-descriptions-item>
          <el-descriptions-item label="设备厂商" v-if="detail.vendor">
            <el-tag type="info" effect="plain">{{ detail.vendor }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="发送流量">{{ formatBytes(detail.bytes_sent) }}</el-descriptions-item>
          <el-descriptions-item label="接收流量">{{ formatBytes(detail.bytes_recv) }}</el-descriptions-item>
          <el-descriptions-item label="发送包数">{{ detail.packets_sent }}</el-descriptions-item>
          <el-descriptions-item label="接收包数">{{ detail.packets_recv }}</el-descriptions-item>
          <el-descriptions-item label="总流数">{{ detail.flow_count }}</el-descriptions-item>
          <el-descriptions-item label="活跃时长">{{ formatDuration(detail.active_seconds) }}</el-descriptions-item>
          <el-descriptions-item label="首次活动">{{ detail.first_seen ? formatTime(detail.first_seen) : '-' }}</el-descriptions-item>
          <el-descriptions-item label="最后活动">{{ detail.last_seen ? formatTime(detail.last_seen) : '-' }}</el-descriptions-item>
          <el-descriptions-item label="风险分" v-if="detail.risk_score > 0">
            <el-tag :type="riskTagType(detail.risk_level)" size="small">{{ detail.risk_score }} ({{ detail.risk_level }})</el-tag>
          </el-descriptions-item>
        </el-descriptions>

        <el-tabs type="border-card">
          <el-tab-pane label="协议分布">
            <div v-for="p in detail.top_protocols" :key="p.protocol" class="detail-row">
              <span class="detail-name">{{ p.protocol }}</span>
              <span class="detail-bar-bg"><span class="detail-bar" :style="{ width: pct(p.bytes, detail.bytes_sent + detail.bytes_recv) + '%' }" /></span>
              <span class="detail-val">{{ formatBytes(p.bytes) }}</span>
            </div>
            <el-empty v-if="detail.top_protocols.length === 0" description="暂无协议数据" :image-size="60" />
          </el-tab-pane>
          <el-tab-pane label="访问域名">
            <div v-for="d in detail.top_domains" :key="d.host" class="detail-row">
              <span class="detail-name" :title="d.host">{{ d.host }}</span>
              <span class="detail-bar-bg"><span class="detail-bar bar-green" :style="{ width: pct(d.bytes, detail.bytes_sent + detail.bytes_recv) + '%' }" /></span>
              <span class="detail-val">{{ formatBytes(d.bytes) }}</span>
            </div>
            <el-empty v-if="detail.top_domains.length === 0" description="暂无域名数据" :image-size="60" />
          </el-tab-pane>
          <el-tab-pane label="通信对端">
            <div v-for="p in detail.top_peers" :key="p.ip" class="detail-row">
              <span class="detail-name">{{ p.ip }}</span>
              <el-tag size="small" :type="p.direction === 'egress' ? 'primary' : 'success'" style="margin:0 6px">
                {{ p.direction === 'egress' ? '→ 出' : '← 入' }}
              </el-tag>
              <span class="detail-bar-bg"><span class="detail-bar bar-orange" :style="{ width: pct(p.bytes_total, detail.bytes_sent + detail.bytes_recv) + '%' }" /></span>
              <span class="detail-val">{{ formatBytes(p.bytes_total) }}</span>
            </div>
            <el-empty v-if="detail.top_peers.length === 0" description="暂无对端数据" :image-size="60" />
          </el-tab-pane>
          <el-tab-pane label="目标地区">
            <div v-for="c in detail.top_countries" :key="c.country" class="detail-row">
              <span class="detail-name">{{ c.country }}</span>
              <span class="detail-bar-bg"><span class="detail-bar bar-purple" :style="{ width: pct(c.bytes, detail.bytes_sent + detail.bytes_recv) + '%' }" /></span>
              <span class="detail-val">{{ formatBytes(c.bytes) }}</span>
            </div>
            <el-empty v-if="detail.top_countries.length === 0" description="暂无地区数据" :image-size="60" />
          </el-tab-pane>
        </el-tabs>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { fetchDeviceProfiles, fetchDeviceProfileDetail } from '@/services/api'
import type { DeviceProfile, DeviceProfileList } from '@/types'

const loading = ref(false)
const error = ref('')
const timeRange = ref('1h')
const sortBy = ref('bytes')
const page = ref(1)

const list = reactive<DeviceProfileList>({ devices: [], total: 0, page: 1, size: 20 })
const detailVisible = ref(false)
const detail = reactive<DeviceProfile>({
  ip: '', mac: '', vendor: '', hostname: '',
  bytes_sent: 0, bytes_recv: 0, packets_sent: 0, packets_recv: 0,
  flow_count: 0, first_seen: null, last_seen: null, active_seconds: 0,
  top_protocols: [], top_services: [], top_domains: [], top_peers: [], top_countries: [],
  risk_score: 0, risk_events: 0, risk_level: '',
})

const dialogTitle = computed(() => {
  const parts = ['设备画像']
  if (detail.ip) parts.push('— ' + detail.ip)
  if (detail.mac) parts.push('(' + detail.mac + ')')
  return parts.join(' ')
})

async function fetchData() {
  loading.value = true
  error.value = ''
  try {
    const data = await fetchDeviceProfiles(timeRange.value, page.value, 20, sortBy.value)
    Object.assign(list, data)
  } catch (e: any) {
    error.value = '获取设备画像失败: ' + (e?.message || '')
  } finally {
    loading.value = false
  }
}

async function selectDevice(dev: DeviceProfile) {
  detailVisible.value = true
  Object.assign(detail, dev)
  try {
    const ipOrMac = dev.mac || dev.ip
    const data = await fetchDeviceProfileDetail(ipOrMac, timeRange.value)
    if (data) Object.assign(detail, data)
  } catch {
    // 保留卡片数据
  }
}

function formatBytes(b: number): string {
  if (b === 0) return '0 B'
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(b) / Math.log(1024))
  return (b / Math.pow(1024, i)).toFixed(i > 1 ? 1 : 0) + ' ' + u[i]
}

function formatTime(s: string): string {
  const d = new Date(s)
  return `${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}

function formatDuration(sec: number): string {
  if (sec < 60) return sec + 's'
  if (sec < 3600) return Math.floor(sec / 60) + 'm' + (sec % 60) + 's'
  return Math.floor(sec / 3600) + 'h' + Math.floor((sec % 3600) / 60) + 'm'
}

function pct(val: number, total: number): number {
  return total > 0 ? +(val / total * 100).toFixed(1) : 0
}

function riskTagType(level: string): string {
  return { critical: 'danger', high: 'warning', medium: 'warning', low: 'info' }[level] || 'info'
}

onMounted(fetchData)
</script>

<style scoped>
.profiles-page { max-width: 1400px; margin: 0 auto; }
.section-title { font-size: 16px; font-weight: 600; display: flex; align-items: center; }

.device-card { cursor: pointer; transition: box-shadow 0.2s; }
.device-card:hover { box-shadow: 0 2px 12px rgba(0,0,0,0.12); }
.device-card.risk-critical { border-top: 3px solid #e61919; }
.device-card.risk-high { border-top: 3px solid #ff8c00; }
.device-card.risk-medium { border-top: 3px solid #f5c518; }
.device-card.risk-low { border-top: 3px solid #52c41a; }

.device-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.device-ip { font-family: 'SF Mono', monospace; font-size: 15px; font-weight: 700; color: #303133; }
.device-mac-row { display: flex; align-items: center; gap: 6px; margin-bottom: 8px; font-size: 11px; }
.device-mac-row .mac-label { font-family: 'SF Mono', monospace; color: #909399; letter-spacing: 0.5px; }
.device-stats { display: flex; flex-direction: column; gap: 4px; }
.stat-row { display: flex; justify-content: space-between; font-size: 12px; }
.stat-label { color: #909399; }
.stat-val { color: #303133; font-weight: 500; }

.device-services { margin-top: 10px; padding-top: 8px; border-top: 1px solid #ebeef5; }
.services-label { font-size: 11px; color: #909399; margin-bottom: 4px; }
.services-tags { display: flex; flex-wrap: wrap; gap: 4px; }
.service-tag { max-width: 100px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.detail-row { display: flex; align-items: center; gap: 8px; padding: 6px 0; }
.detail-name { min-width: 100px; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.detail-bar-bg { flex: 1; height: 6px; background: #e4e7ed; border-radius: 3px; }
.detail-bar { display: block; height: 100%; background: #409eff; border-radius: 3px; transition: width 0.3s; }
.detail-bar.bar-green { background: #67c23a; }
.detail-bar.bar-orange { background: #e6a23c; }
.detail-bar.bar-purple { background: #9b59b6; }
.detail-val { min-width: 70px; text-align: right; font-size: 12px; color: #606266; }
</style>
