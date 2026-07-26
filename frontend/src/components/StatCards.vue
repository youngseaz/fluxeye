<template>
  <el-row :gutter="16">
    <el-col :span="6" v-for="card in cards" :key="card.label">
      <el-card shadow="hover" class="stat-card">
        <div class="stat-content">
          <div class="stat-icon" :style="{ color: card.color }">
            <el-icon :size="32"><component :is="card.icon" /></el-icon>
          </div>
          <div class="stat-info">
            <div class="stat-value">{{ card.value }}</div>
            <div class="stat-label">{{ card.label }}</div>
          </div>
        </div>
      </el-card>
    </el-col>
  </el-row>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { DataLine, Promotion, Connection, Tickets } from '@element-plus/icons-vue'
import type { TrafficOverview } from '@/types'

const props = defineProps<{
  data: TrafficOverview | null
}>()

function formatBps(bps: number): string {
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(2)} Gbps`
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(2)} Mbps`
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(2)} Kbps`
  return `${bps.toFixed(2)} bps`
}

function formatPps(pps: number): string {
  if (pps >= 1_000_000) return `${(pps / 1_000_000).toFixed(2)} Mpps`
  if (pps >= 1_000) return `${(pps / 1_000).toFixed(2)} Kpps`
  return `${pps.toFixed(2)} pps`
}

const cards = computed(() => [
  {
    icon: DataLine,
    label: '总流量',
    value: formatBps(props.data?.total_bps ?? 0),
    color: '#409eff',
  },
  {
    icon: Promotion,
    label: '包速率',
    value: formatPps(props.data?.total_pps ?? 0),
    color: '#67c23a',
  },
  {
    icon: Connection,
    label: '活跃流',
    value: String(props.data?.active_flows ?? 0),
    color: '#e6a23c',
  },
  {
    icon: Tickets,
    label: '连接数',
    value: String(props.data?.total_connections ?? 0),
    color: '#f56c6c',
  },
])
</script>

<style scoped>
.stat-card {
  border-radius: 8px;
}
.stat-content {
  display: flex;
  align-items: center;
  gap: 16px;
}
.stat-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 56px;
  height: 56px;
  border-radius: 12px;
  background: rgba(64, 158, 255, 0.08);
}
.stat-info {
  flex: 1;
}
.stat-value {
  font-size: 24px;
  font-weight: 700;
  color: #303133;
  line-height: 1.2;
}
.stat-label {
  font-size: 13px;
  color: #909399;
  margin-top: 4px;
}
</style>
