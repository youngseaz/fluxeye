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
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { fetchDeviceProfiles } from '@/services/api'
import type { DeviceProfile, DeviceProfileList } from '@/types'

const router = useRouter()
const loading = ref(false)
const error = ref('')
const timeRange = ref('1h')
const sortBy = ref('bytes')
const page = ref(1)

const list = reactive<DeviceProfileList>({ devices: [], total: 0, page: 1, size: 20 })

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

function selectDevice(dev: DeviceProfile) {
  router.push('/profiles/' + (dev.ip || dev.mac))
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
