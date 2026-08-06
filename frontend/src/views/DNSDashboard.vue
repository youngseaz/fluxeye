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
          <template #header><span>查询域名 Top {{ topLimit }}</span></template>
          <div ref="domainChartRef" class="chart-container chart-sm"></div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header><span>查询客户端 Top {{ topLimit }}</span></template>
          <div ref="clientChartRef" class="chart-container chart-sm"></div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 域名明细表 -->
    <el-card shadow="hover" style="margin-top: 16px">
      <template #header>
        <span>查询域名明细</span>
        <el-tag size="small" style="margin-left: 8px" type="info">按查询次数排序</el-tag>
      </template>
      <el-table :data="topDomains" size="small" stripe style="width: 100%">
        <el-table-column type="index" label="#" width="55" />
        <el-table-column prop="host" label="域名" min-width="260" show-overflow-tooltip>
          <template #default="{ row }">
            <code style="font-size: 12px">{{ row.host }}</code>
          </template>
        </el-table-column>
        <el-table-column prop="query_count" label="查询次数" width="110" align="right" sortable />
        <el-table-column prop="percentage" label="占比" width="120" align="right">
          <template #default="{ row }">
            <el-progress :percentage="row.percentage" :stroke-width="12" />
          </template>
        </el-table-column>
        <el-table-column label="流量" width="120" align="right">
          <template #default="{ row }">{{ formatBytes(row.bytes_total) }}</template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, shallowRef, watch, type ShallowRef } from 'vue'
import * as echarts from 'echarts'
import {
  DataLine, QuestionFilled, Monitor, Connection, Refresh,
} from '@element-plus/icons-vue'
import {
  fetchDnsOverview, fetchDnsTopDomains, fetchDnsTopClients, fetchDnsTimeseries,
} from '@/services/api'
import type { DnsOverview, DnsDomainStat, DnsClientStat, DnsTimePoint } from '@/types'

const timeRange = ref('1h')
const topLimit = 20

const overview = ref<DnsOverview | null>(null)
const topDomains = ref<DnsDomainStat[]>([])
const topClients = ref<DnsClientStat[]>([])
const timeseries = ref<DnsTimePoint[]>([])
const loading = ref(false)

const tsChartRef = ref<HTMLElement | null>(null)
const domainChartRef = ref<HTMLElement | null>(null)
const clientChartRef = ref<HTMLElement | null>(null)
const tsChart = shallowRef<echarts.ECharts | null>(null)
const domainChart = shallowRef<echarts.ECharts | null>(null)
const clientChart = shallowRef<echarts.ECharts | null>(null)

function formatBytes(bytes: number): string {
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`
  return `${bytes} B`
}

function formatRate(qps: number): string {
  if (qps >= 1000) return `${(qps / 1000).toFixed(2)}K`
  return qps.toFixed(2)
}

const cards = computed(() => [
  { icon: QuestionFilled, label: 'DNS 查询', value: String(overview.value?.total_queries ?? 0), color: '#409eff' },
  { icon: DataLine, label: 'DNS 流量', value: formatBytes(overview.value?.total_bytes ?? 0), color: '#67c23a' },
  { icon: Connection, label: '独立域名', value: String(overview.value?.distinct_domains ?? 0), color: '#e6a23c' },
  { icon: Monitor, label: '查询速率', value: `${formatRate(overview.value?.query_rate ?? 0)} QPS`, color: '#f56c6c' },
])

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

function initBarChart(instance: ShallowRef<echarts.ECharts | null>, el: HTMLElement | null) {
  if (!el) return
  instance.value = echarts.init(el)
  instance.value.setOption({
    grid: { left: 10, right: 20, top: 10, bottom: 10, containLabel: true },
    xAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: {
        fontSize: 11,
        color: '#909399',
        formatter: (v: number) => {
          if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`
          if (v >= 1_000) return `${(v / 1_000).toFixed(1)}k`
          return String(v)
        },
      },
      splitLine: { lineStyle: { color: '#f0f0f0' } },
    },
    yAxis: {
      type: 'category',
      inverse: true,
      axisLabel: { fontSize: 11, color: '#303133', width: 130, overflow: 'truncate' },
    },
    series: [{
      type: 'bar',
      barMaxWidth: 16,
      itemStyle: { color: '#409eff', borderRadius: [0, 3, 3, 0] },
      label: {
        show: true,
        position: 'right',
        fontSize: 11,
        color: '#909399',
        formatter: (p: any) => {
          const v = p.value ?? 0
          if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`
          if (v >= 1_000) return `${(v / 1_000).toFixed(1)}k`
          return String(v)
        },
      },
      data: [] as { value: number; name: string }[],
    }],
  })
}

function updateDomainChart() {
  if (!domainChart.value) return
  const data = topDomains.value.slice(0, topLimit).map((d) => ({
    name: d.host,
    value: d.query_count,
  }))
  domainChart.value.setOption({ series: [{ data }] })
}

function updateClientChart() {
  if (!clientChart.value) return
  const data = topClients.value.slice(0, topLimit).map((d) => ({
    name: d.src_ip,
    value: d.query_count,
  }))
  clientChart.value.setOption({ series: [{ data }] })
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
    const [ov, dm, cl, ts] = await Promise.all([
      fetchDnsOverview(timeRange.value),
      fetchDnsTopDomains(timeRange.value, topLimit),
      fetchDnsTopClients(timeRange.value, topLimit),
      fetchDnsTimeseries(intervalForRange(), timeRange.value),
    ])
    overview.value = ov
    topDomains.value = dm
    topClients.value = cl
    timeseries.value = ts
    updateTsChart()
    updateDomainChart()
    updateClientChart()
  } catch {
    // 静默
  } finally {
    loading.value = false
  }
}

let refreshTimer: ReturnType<typeof setInterval> | null = null

function resizeCharts() {
  tsChart.value?.resize()
  domainChart.value?.resize()
  clientChart.value?.resize()
}

onMounted(async () => {
  initTsChart()
  initBarChart(domainChart, domainChartRef.value)
  initBarChart(clientChart, clientChartRef.value)
  await refreshAll()
  refreshTimer = setInterval(refreshAll, 15000)
  window.addEventListener('resize', resizeCharts)
})

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer)
  window.removeEventListener('resize', resizeCharts)
  tsChart.value?.dispose()
  domainChart.value?.dispose()
  clientChart.value?.dispose()
})

watch([domainChartRef, clientChartRef], () => {
  // 元素挂载后初始化图表
  if (!domainChart.value && domainChartRef.value) {
    initBarChart(domainChart, domainChartRef.value)
    updateDomainChart()
  }
  if (!clientChart.value && clientChartRef.value) {
    initBarChart(clientChart, clientChartRef.value)
    updateClientChart()
  }
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
</style>
