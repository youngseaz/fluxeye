<template>
  <el-card shadow="hover" class="chart-card">
    <template #header>
      <div class="chart-header">
        <span>Top IP 流量排行</span>
        <el-tag size="small" type="info">{{ props.data?.time_range ?? '' }}</el-tag>
      </div>
    </template>
    <div ref="chartRef" class="chart-container"></div>
  </el-card>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch, shallowRef } from 'vue'
import * as echarts from 'echarts'
import type { TopTalkersResponse } from '@/types'

const props = defineProps<{
  data: TopTalkersResponse | null
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
        return `${p.name}<br/>流量: ${(p.value / 1_000_000_000).toFixed(2)} GB`
      },
    },
    grid: { left: 100, right: 30, top: 10, bottom: 30 },
    xAxis: {
      type: 'value',
      axisLabel: {
        formatter: (v: number) => {
          if (v >= 1_000_000_000) return `${(v / 1_000_000_000).toFixed(1)}G`
          if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`
          return String(v)
        },
      },
      splitLine: { lineStyle: { color: '#f0f0f0' } },
    },
    yAxis: {
      type: 'category',
      axisLabel: { fontSize: 11 },
      data: [] as string[],
    },
    series: [{
      type: 'bar',
      barWidth: 16,
      itemStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
          { offset: 0, color: 'rgba(64,158,255,0.6)' },
          { offset: 1, color: 'rgba(64,158,255,1)' },
        ]),
        borderRadius: [0, 4, 4, 0],
      },
      data: [] as number[],
    }],
  })
}

function updateChart() {
  if (!chart.value || !props.data?.talkers) return
  const ips = props.data.talkers.map((t) => t.ip)
  const values = props.data.talkers.map((t) => t.bytes_total)
  chart.value.setOption({
    yAxis: { data: ips.reverse() },
    series: [{ data: values.reverse() }],
  })
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
  height: 100%;
}
.chart-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-weight: 600;
}
.chart-container {
  width: 100%;
  height: 300px;
}
</style>
