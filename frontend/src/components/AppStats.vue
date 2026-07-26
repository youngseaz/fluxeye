<template>
  <el-card shadow="hover">
    <template #header>
      <div class="card-header">
        <span>应用流量统计</span>
        <el-tag size="small" type="info">{{ rangeLabel }}</el-tag>
      </div>
    </template>
    <el-skeleton :rows="5" animated v-if="!data" />
    <div v-else-if="data.length === 0" class="empty">暂无数据</div>
    <div v-else class="app-list">
      <div v-for="(item, i) in data" :key="item.protocol" class="app-row">
        <span class="rank">{{ i + 1 }}</span>
        <div class="app-info">
          <div class="app-top">
            <span :class="['proto-tag', 'proto-' + (item.protocol || 'unknown').toLowerCase()]">
              {{ item.protocol.toUpperCase() }}
            </span>
            <span class="app-flows">{{ item.flow_count }} 条流</span>
          </div>
          <div class="app-bar-bg">
            <div class="app-bar" :style="{ width: item.percentage + '%' }" />
          </div>
        </div>
        <span class="app-traffic">{{ formatBytes(item.bytes_total) }}</span>
        <span class="app-pct">{{ item.percentage.toFixed(1) }}%</span>
      </div>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import type { AppStat } from '@/types'

defineProps<{
  data: AppStat[] | null
  rangeLabel?: string
}>()

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return (bytes / Math.pow(1024, i)).toFixed(i > 1 ? 1 : 0) + ' ' + units[i]
}
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-weight: 600;
}
.empty {
  text-align: center;
  color: #909399;
  padding: 24px 0;
  font-size: 13px;
}
.app-list {
  max-height: 360px;
  overflow-y: auto;
}
.app-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 0;
  border-bottom: 1px solid #f0f0f0;
}
.app-row:last-child {
  border-bottom: none;
}
.rank {
  width: 20px;
  text-align: center;
  font-size: 12px;
  color: #909399;
  font-weight: 600;
}
.app-info {
  flex: 1;
  min-width: 0;
}
.app-top {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 4px;
}
.app-flows {
  font-size: 11px;
  color: #909399;
}
.app-bar-bg {
  height: 4px;
  background: #e4e7ed;
  border-radius: 2px;
}
.app-bar {
  height: 100%;
  background: linear-gradient(90deg, #67c23a, #85ce61);
  border-radius: 2px;
  transition: width 0.3s;
}
.app-traffic {
  font-size: 12px;
  color: #606266;
  white-space: nowrap;
  min-width: 70px;
  text-align: right;
}
.app-pct {
  font-size: 11px;
  color: #909399;
  min-width: 40px;
  text-align: right;
}
</style>
