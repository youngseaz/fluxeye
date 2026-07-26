<template>
  <div class="dashboard">
    <!-- 加载状态 -->
    <el-skeleton :rows="3" animated v-if="store.loading && !store.overview" />

    <!-- 错误提示 -->
    <el-alert
      v-if="store.error"
      :title="store.error"
      type="error"
      show-icon
      closable
      style="margin-bottom: 16px"
    />

    <!-- 顶部指标卡 -->
    <StatCards :data="store.overview" />

    <!-- 流量时序图 -->
    <el-row :gutter="16" style="margin-top: 16px">
      <el-col :span="24">
        <TrafficChart :data="store.timeSeries?.data ?? []" />
      </el-col>
    </el-row>

    <!-- 协议分布 + Top Talkers -->
    <el-row :gutter="16" style="margin-top: 16px">
      <el-col :span="12">
        <ProtocolPie :data="store.protocols" />
      </el-col>
      <el-col :span="12">
        <TopTalkers :data="store.topTalkers" />
      </el-col>
    </el-row>

    <!-- 域名统计 + 应用服务统计 -->
    <el-row :gutter="16" style="margin-top: 16px">
      <el-col :span="12">
        <DomainStats :data="domains" :range-label="store.timeRange" />
      </el-col>
      <el-col :span="12">
        <ServiceStats :data="services" :range-label="store.timeRange" />
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { useTrafficStore } from '@/stores/traffic'
import { fetchTopDomains, fetchServicesStats } from '@/services/api'
import type { DomainStat, ServiceStat } from '@/types'
import StatCards from '@/components/StatCards.vue'
import TrafficChart from '@/components/TrafficChart.vue'
import ProtocolPie from '@/components/ProtocolPie.vue'
import TopTalkers from '@/components/TopTalkers.vue'
import DomainStats from '@/components/DomainStats.vue'
import ServiceStats from '@/components/ServiceStats.vue'

const store = useTrafficStore()
const domains = ref<DomainStat[] | null>(null)
const services = ref<ServiceStat[] | null>(null)
let statsTimer: ReturnType<typeof setInterval> | null = null

async function refreshStats() {
  try {
    const [d, s] = await Promise.all([
      fetchTopDomains(store.timeRange, 15),
      fetchServicesStats(store.timeRange, 15),
    ])
    domains.value = d
    services.value = s
  } catch {
    // 静默
  }
}

onMounted(async () => {
  await refreshStats()
  statsTimer = setInterval(refreshStats, 15000)
})

onUnmounted(() => {
  if (statsTimer) clearInterval(statsTimer)
})
</script>

<style scoped>
.dashboard {
  max-width: 1400px;
  margin: 0 auto;
}
</style>
