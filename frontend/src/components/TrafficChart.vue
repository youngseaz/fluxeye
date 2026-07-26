<template>
  <el-card shadow="hover" class="chart-card">
    <template #header>
      <div class="chart-header">
        <span>实时流量</span>
        <span class="chart-unit">bps</span>
      </div>
    </template>
    <div ref="chartRef" class="chart-container"></div>
  </el-card>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch, shallowRef } from 'vue'
import * as echarts from 'echarts'
import type { TimePoint } from '@/types'

const props = defineProps<{
  data: TimePoint[]
}>()

const chartRef = ref<HTMLElement | null>(null)
const chart = shallowRef<echarts.ECharts | null>(null)

function initChart() {
  if (!chartRef.value) return
  chart.value = echarts.init(chartRef.value)

  chart.value.setOption({
    tooltip: {
      trigger: 'axis',
      formatter: (params: any) => {
        const p = params[0]
        const ts = p.data[0]
        const val = p.data[1]
        return `${ts}<br/>流量: ${(val / 1_000_000).toFixed(2)} Mbps`
      },
    },
    grid: { left: 60, right: 20, top: 10, bottom: 30 },
    xAxis: {
      type: 'time',
      axisLabel: { fontSize: 11, color: '#909399' },
    },
    yAxis: {
      type: 'value',
      name: 'bps',
      axisLabel: {
        fontSize: 11,
        color: '#909399',
        formatter: (v: number) => {
          if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(0)}M`
          if (v >= 1_000) return `${(v / 1_000).toFixed(0)}K`
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

function updateChart() {
  if (!chart.value || !props.data.length) return
  const seriesData = props.data.map((p) => [p.timestamp, p.bps] as [string, number])
  chart.value.setOption({ series: [{ data: seriesData }] })
}

watch(() => props.data, updateChart, { deep: true })

onMounted(() => {
  initChart()
  updateChart()
  const handleResize = () => chart.value?.resize()
  window.addEventListener('resize', handleResize)
  onUnmounted(() => {
    window.removeEventListener('resize', handleResize)
    chart.value?.dispose()
  })
})
</script>

<style scoped>
.chart-card {
  border-radius: 8px;
}
.chart-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-weight: 600;
}
.chart-unit {
  font-size: 12px;
  color: #909399;
  font-weight: 400;
}
.chart-container {
  width: 100%;
  height: 280px;
}
</style>
