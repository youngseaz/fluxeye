<template>
  <el-card shadow="hover">
    <template #header>
      <div class="card-header">
        <span>访问域名统计</span>
        <el-tag size="small" type="info">{{ rangeLabel }}</el-tag>
      </div>
    </template>
    <el-skeleton :rows="5" animated v-if="!data" />
    <div v-else-if="data.length === 0" class="empty">暂无数据</div>
    <div v-else class="domain-list">
      <div v-for="(item, i) in data" :key="item.host" class="domain-row">
        <span class="rank">{{ i + 1 }}</span>
        <div class="domain-info">
          <span class="domain-name" :title="item.host">{{ item.host }}</span>
          <div class="domain-bar-bg">
            <div class="domain-bar" :style="{ width: item.percentage + '%' }" />
          </div>
        </div>
        <span class="domain-traffic">{{ formatBytes(item.bytes_total) }}</span>
      </div>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import type { DomainStat } from '@/types'

defineProps<{
  data: DomainStat[] | null
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
.domain-list {
  max-height: 360px;
  overflow-y: auto;
}
.domain-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 0;
}
.rank {
  width: 20px;
  text-align: center;
  font-size: 12px;
  color: #909399;
  font-weight: 600;
}
.domain-info {
  flex: 1;
  min-width: 0;
}
.domain-name {
  display: block;
  font-size: 12px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.domain-bar-bg {
  height: 4px;
  background: #e4e7ed;
  border-radius: 2px;
  margin-top: 3px;
}
.domain-bar {
  height: 100%;
  background: linear-gradient(90deg, #409eff, #79bbff);
  border-radius: 2px;
  transition: width 0.3s;
}
.domain-traffic {
  font-size: 12px;
  color: #606266;
  white-space: nowrap;
  min-width: 70px;
  text-align: right;
}
</style>
