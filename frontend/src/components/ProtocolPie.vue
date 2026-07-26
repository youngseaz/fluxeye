<template>
  <el-card shadow="hover" class="chart-card">
    <template #header>
      <div class="chart-header">
        <span>协议分布</span>
        <el-tag size="small" type="info">{{ props.data?.time_range ?? '' }}</el-tag>
      </div>
    </template>
    <div ref="chartRef" class="chart-container"></div>
  </el-card>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch, shallowRef } from 'vue'
import * as echarts from 'echarts'
import type { ProtocolDistribution } from '@/types'

const props = defineProps<{
  data: ProtocolDistribution | null
}>()

const chartRef = ref<HTMLElement | null>(null)
const chart = shallowRef<echarts.ECharts | null>(null)

const PROTO_COLORS: Record<string, string> = {
  http: '#409eff',
  tls: '#67c23a',
  dns: '#e6a23c',
  quic: '#f56c6c',
  ssh: '#909399',
  smtp: '#b37feb',
  dhcp: '#36cfc9',
  rtmp: '#ff85c0',
  unknown: '#d9d9d9',
}

function initChart() {
  if (!chartRef.value) return
  chart.value = echarts.init(chartRef.value)
  chart.value.setOption({
    tooltip: {
      trigger: 'item',
      formatter: '{b}: {c} ({d}%)',
    },
    series: [{
      type: 'pie',
      radius: ['45%', '70%'],
      avoidLabelOverlap: true,
      label: {
        show: true,
        formatter: '{b}\n{d}%',
        fontSize: 11,
      },
      emphasis: {
        label: { show: true, fontSize: 14, fontWeight: 'bold' },
      },
      data: [] as { value: number; name: string; itemStyle?: { color: string } }[],
    }],
  })
}

function updateChart() {
  if (!chart.value || !props.data?.protocols) return
  const pieData = props.data.protocols.map((p) => ({
    value: p.bytes_total,
    name: p.l7_proto.toUpperCase(),
    itemStyle: { color: PROTO_COLORS[p.l7_proto] || '#d9d9d9' },
  }))
  chart.value.setOption({ series: [{ data: pieData }] })
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
