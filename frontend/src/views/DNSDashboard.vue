<template>
  <div class="dns-dashboard">
    <!-- 加载状态 -->
    <el-skeleton :rows="3" animated v-if="loading && !overview" />

    <!-- 时间范围选择 -->
    <div class="dns-toolbar">
      <span class="dns-title">DNS 仪表盘</span>
      <el-radio-group v-model="timeRange" size="small" @change="refreshAll">
        <el-radio-button value="5m">5分钟</el-radio-button>
        <el-radio-button value="1h">1小时</el-radio-button>
        <el-radio-button value="6h">6小时</el-radio-button>
        <el-radio-button value="24h">24小时</el-radio-button>
      </el-radio-group>
      <el-button size="small" :icon="Refresh" @click="refreshAll">刷新</el-button>
    </div>

    <!-- 统计卡片 -->
    <el-row :gutter="16">
      <el-col :span="6" v-for="card in cards" :key="card.label">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" :style="{ color: card.color }">
              <el-icon :size="30"><component :is="card.icon" /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ card.value }}</div>
              <div class="stat-label">{{ card.label }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- DNS 活动时序 -->
    <el-row :gutter="16" style="margin-top: 16px">
      <el-col :span="24">
        <el-card shadow="hover">
          <template #header>
            <div class="chart-header">
              <span>DNS 查询活动</span>
              <span class="chart-unit">查询数 / 时间桶</span>
            </div>
          </template>
          <div ref="tsChartRef" class="chart-container"></div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 查询域名 Top + 客户端 Top -->
    <el-row :gutter="16" style="margin-top: 16px">
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <span>查询域名 Top {{ topLimit }}</span>
            <el-tag size="small" type="info" style="margin-left: 8px">次数 / 域名</el-tag>
          </template>
          <div class="top-list">
            <div class="top-list-row" v-for="d in sortedTopDomains" :key="d.host">
              <span class="top-name" :title="d.host">{{ d.host }}</span>
              <span class="top-count">{{ d.query_count }}</span>
            </div>
            <el-empty v-if="topDomains.length === 0" description="暂无数据" :image-size="40" />
          </div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <span>查询客户端 Top {{ topLimit }}</span>
            <el-tag size="small" type="info" style="margin-left: 8px">客户端 / 次数</el-tag>
          </template>
          <div class="top-list">
            <div class="top-list-row" v-for="c in sortedTopClients" :key="c.src_ip">
              <span class="top-name" :title="c.src_ip">{{ c.src_ip }}</span>
              <span class="top-count">{{ c.query_count }}</span>
            </div>
            <el-empty v-if="topClients.length === 0" description="暂无数据" :image-size="40" />
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 域名明细表 -->
    <el-card shadow="hover" style="margin-top: 16px">
      <template #header>
        <div class="detail-header">
          <span>
            查询域名明细
            <el-tag size="small" style="margin-left: 8px" type="info">每条 DNS 查询一行 · 按时间倒序</el-tag>
          </span>
          <div class="detail-filter">
            <el-input
              v-model="detailDomain"
              placeholder="按域名搜索"
              clearable
              size="small"
              style="width: 180px"
              @keyup.enter="refreshAll"
            />
            <el-input
              v-model="detailClient"
              placeholder="按客户端 IP/MAC"
              clearable
              size="small"
              style="width: 170px; margin-left: 8px"
              @keyup.enter="refreshAll"
            />
            <el-button size="small" type="primary" :icon="Search" style="margin-left: 8px" @click="refreshAll">查询</el-button>
            <el-button size="small" style="margin-left: 4px" @click="resetDetailFilter">重置</el-button>
          </div>
        </div>
      </template>
      <el-table :data="dnsQueries" size="small" stripe style="width: 100%">
        <el-table-column type="index" label="#" width="55" />
        <el-table-column label="时间" width="160" sortable prop="last_seen">
          <template #default="{ row }">
            {{ formatTime(row.last_seen) }}
          </template>
        </el-table-column>
        <el-table-column label="请求客户端" min-width="180">
          <template #default="{ row }">
            <div>{{ row.client_ip }}</div>
            <div style="font-size: 11px; color: #909399">{{ row.client_mac || '-' }}</div>
          </template>
        </el-table-column>
        <el-table-column prop="server_ip" label="服务端" min-width="130">
          <template #default="{ row }">
            {{ row.server_ip || '-' }}
          </template>
        </el-table-column>
        <el-table-column label="DNS 请求" min-width="220" show-overflow-tooltip>
          <template #default="{ row }">
            <div class="dns-info" :title="row.request_info">{{ row.request_info || '未知' }}</div>
          </template>
        </el-table-column>
        <el-table-column label="DNS 响应" min-width="220" show-overflow-tooltip>
          <template #default="{ row }">
            <div class="dns-info" :title="row.response_info">{{ row.response_info || '未知' }}</div>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, shallowRef } from 'vue'
import * as echarts from 'echarts'
import {
  DataLine, QuestionFilled, Monitor, Connection, Refresh, Search,
} from '@element-plus/icons-vue'
import {
  fetchDnsOverview, fetchDnsTopDomains, fetchDnsTopClients, fetchDnsTimeseries, fetchDnsQueries,
} from '@/services/api'
import type { DnsOverview, DnsDomainStat, DnsClientStat, DnsTimePoint, DnsQueryDetail } from '@/types'

const timeRange = ref('1h')
const topLimit = 20

const overview = ref<DnsOverview | null>(null)
const topDomains = ref<DnsDomainStat[]>([])
const topClients = ref<DnsClientStat[]>([])
const timeseries = ref<DnsTimePoint[]>([])
const dnsQueries = ref<DnsQueryDetail[]>([])
const detailDomain = ref('')
const detailClient = ref('')
const loading = ref(false)

const tsChartRef = ref<HTMLElement | null>(null)
const tsChart = shallowRef<echarts.ECharts | null>(null)

function formatBytes(bytes: number): string {
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`
  return `${bytes} B`
}

function formatRate(qps: number): string {
  if (qps >= 1000) return `${(qps / 1000).toFixed(2)}K`
  return qps.toFixed(2)
}

function formatTime(ts: string): string {
  if (!ts) return '-'
  const d = new Date(ts)
  if (isNaN(d.getTime())) return ts
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

const cards = computed(() => [
  { icon: QuestionFilled, label: 'DNS 查询', value: String(overview.value?.total_queries ?? 0), color: '#409eff' },
  { icon: DataLine, label: 'DNS 流量', value: formatBytes(overview.value?.total_bytes ?? 0), color: '#67c23a' },
  { icon: Connection, label: '独立域名', value: String(overview.value?.distinct_domains ?? 0), color: '#e6a23c' },
  { icon: Monitor, label: '查询速率', value: `${formatRate(overview.value?.query_rate ?? 0)} QPS`, color: '#f56c6c' },
])

// 查询域名 Top：按请求次数从高到低排序
const sortedTopDomains = computed(() =>
  [...topDomains.value].sort((a, b) => b.query_count - a.query_count)
)

// 查询客户端 Top：按请求次数从高到低排序
const sortedTopClients = computed(() =>
  [...topClients.value].sort((a, b) => b.query_count - a.query_count)
)

function initTsChart() {
  if (!tsChartRef.value) return
  tsChart.value = echarts.init(tsChartRef.value)
  tsChart.value.setOption({
    tooltip: {
      trigger: 'axis',
      formatter: (params: any) => {
        const p = params[0]
        return `${p.data[0]}<br/>查询数: ${p.data[1]}`
      },
    },
    // containLabel: 确保 Y 轴标签完整显示；top: 50 给轴名称「查询数」留足空间，避免顶部裁剪
    grid: { left: 10, right: 20, top: 50, bottom: 10, containLabel: true },
    xAxis: {
      type: 'time',
      axisLabel: { fontSize: 11, color: '#909399', hideOverlap: true },
    },
    yAxis: {
      type: 'value',
      name: '查询数',
      nameLocation: 'end',
      nameGap: 10,
      min: 0,
      nameTextStyle: { fontSize: 12, color: '#606266' },
      minInterval: 1,
      axisLabel: {
        fontSize: 11,
        color: '#909399',
        // 大数值缩写，避免标签被截断
        formatter: (v: number) => {
          if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`
          if (v >= 1_000) return `${(v / 1_000).toFixed(1)}k`
          return String(v)
        },
      },
      splitLine: { lineStyle: { color: '#f0f0f0' } },
    },
    series: [{
      type: 'line',
      smooth: true,
      showSymbol: false,
      lineStyle: { width: 2, color: '#409eff' },
      areaStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: 'rgba(64,158,255,0.3)' },
          { offset: 1, color: 'rgba(64,158,255,0.02)' },
        ]),
      },
      data: [] as [string, number][],
    }],
  })
}

function updateTsChart() {
  if (!tsChart.value) return
  const data = timeseries.value.map((p) => [p.timestamp, p.query_count] as [string, number])
  tsChart.value.setOption({ series: [{ data }] })
}

function intervalForRange(): string {
  const unit = timeRange.value.slice(-1)
  const val = parseInt(timeRange.value, 10)
  if (unit === 'm') {
    if (val <= 5) return '10s'
    if (val <= 60) return '60s'
  }
  if (val >= 24) return '600s'
  return '300s'
}

async function refreshAll() {
  loading.value = true
  try {
    // 逐项容错：单个端点失败不影响其他数据更新
    const results = await Promise.allSettled([
      fetchDnsOverview(timeRange.value),
      fetchDnsTopDomains(timeRange.value, topLimit),
      fetchDnsTopClients(timeRange.value, topLimit),
      fetchDnsTimeseries(intervalForRange(), timeRange.value),
      fetchDnsQueries(timeRange.value, 100, detailDomain.value, detailClient.value),
    ])
    if (results[0].status === 'fulfilled') overview.value = results[0].value
    if (results[1].status === 'fulfilled') topDomains.value = results[1].value
    if (results[2].status === 'fulfilled') topClients.value = results[2].value
    if (results[3].status === 'fulfilled') timeseries.value = results[3].value
    if (results[4].status === 'fulfilled') dnsQueries.value = results[4].value
    updateTsChart()
  } finally {
    loading.value = false
  }
}

function resetDetailFilter() {
  detailDomain.value = ''
  detailClient.value = ''
  refreshAll()
}

let refreshTimer: ReturnType<typeof setInterval> | null = null

function resizeCharts() {
  tsChart.value?.resize()
}

onMounted(async () => {
  initTsChart()
  await refreshAll()
  refreshTimer = setInterval(refreshAll, 15000)
  window.addEventListener('resize', resizeCharts)
})

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer)
  window.removeEventListener('resize', resizeCharts)
  tsChart.value?.dispose()
})
</script>

<style scoped>
.dns-dashboard {
  max-width: 1400px;
  margin: 0 auto;
}
.dns-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}
.dns-title {
  font-size: 16px;
  font-weight: 600;
  color: #303133;
}
.stat-card .stat-content {
  display: flex;
  align-items: center;
}
.stat-card .stat-icon {
  margin-right: 12px;
}
.stat-card .stat-value {
  font-size: 22px;
  font-weight: 600;
  color: #303133;
}
.stat-card .stat-label {
  font-size: 12px;
  color: #909399;
  margin-top: 2px;
}
.chart-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.chart-unit {
  font-size: 12px;
  color: #909399;
}
.chart-container {
  width: 100%;
  height: 280px;
}
.chart-sm {
  height: 320px;
}
.dns-info {
  font-size: 12px;
  color: #303133;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 210px;
}
.detail-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 8px;
}
.detail-filter {
  display: flex;
  align-items: center;
}
/* 查询域名 Top 列表：左边域名，右边次数 */
.top-list {
  height: 320px;
  overflow-y: auto;
  padding-right: 4px;
}
.top-list-row {
  display: flex;
  align-items: center;
  padding: 7px 6px;
  border-bottom: 1px solid #f2f4f7;
}
.top-list-row:last-child {
  border-bottom: none;
}
.top-name {
  flex: 1;
  text-align: left;
  font-size: 13px;
  color: #303133;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.top-count {
  width: 52px;
  font-size: 16px;
  font-weight: 600;
  color: #409eff;
  text-align: right;
  flex-shrink: 0;
}
</style>
