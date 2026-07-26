<template>
  <el-card shadow="hover">
    <template #header>
      <div class="card-header">
        <span>应用服务统计</span>
        <el-tag size="small" type="info">{{ rangeLabel }}</el-tag>
      </div>
    </template>
    <el-skeleton :rows="5" animated v-if="!data" />
    <div v-else-if="data.length === 0" class="empty">暂无数据</div>
    <div v-else class="svc-list">
      <div v-for="(item, i) in data" :key="item.service" class="svc-row">
        <span class="rank">{{ i + 1 }}</span>
        <div class="svc-info">
          <div class="svc-top">
            <span class="svc-name">{{ item.service }}</span>
            <el-tag v-if="item.category" size="small" effect="plain" class="svc-tag">
              {{ item.category }}
            </el-tag>
            <span class="svc-flows">{{ item.flow_count }} 条流</span>
          </div>
          <div class="svc-bar-bg">
            <div class="svc-bar" :style="{ width: item.percentage + '%' }" />
          </div>
        </div>
        <span class="svc-traffic">{{ formatBytes(item.bytes_total) }}</span>
        <span class="svc-pct">{{ item.percentage.toFixed(1) }}%</span>
      </div>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import type { ServiceStat } from '@/types'

defineProps<{
  data: ServiceStat[] | null
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
.svc-list {
  max-height: 400px;
  overflow-y: auto;
}
.svc-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 0;
  border-bottom: 1px solid #f0f0f0;
}
.svc-row:last-child {
  border-bottom: none;
}
.rank {
  width: 20px;
  text-align: center;
  font-size: 12px;
  color: #909399;
  font-weight: 600;
  flex-shrink: 0;
}
.svc-info {
  flex: 1;
  min-width: 0;
}
.svc-top {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 4px;
  flex-wrap: wrap;
}
.svc-name {
  font-size: 13px;
  font-weight: 600;
  color: #303133;
}
.svc-tag {
  font-size: 10px !important;
  height: 18px !important;
  line-height: 18px !important;
  padding: 0 6px !important;
}
.svc-flows {
  font-size: 11px;
  color: #909399;
}
.svc-bar-bg {
  height: 4px;
  background: #e4e7ed;
  border-radius: 2px;
}
.svc-bar {
  height: 100%;
  background: linear-gradient(90deg, #e6a23c, #f5c518);
  border-radius: 2px;
  transition: width 0.3s;
}
.svc-traffic {
  font-size: 12px;
  color: #606266;
  white-space: nowrap;
  min-width: 70px;
  text-align: right;
}
.svc-pct {
  font-size: 11px;
  color: #909399;
  min-width: 40px;
  text-align: right;
}
</style>
