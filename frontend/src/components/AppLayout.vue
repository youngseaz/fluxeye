<template>
  <el-container class="layout-container">
    <!-- 侧边栏 -->
    <el-aside width="220px" class="layout-aside">
      <div class="logo">
        <el-icon :size="24"><Monitor /></el-icon>
        <span class="logo-text">FluxEye</span>
      </div>
      <el-menu
        :default-active="route.path"
        router
        background-color="#304156"
        text-color="#bfcbd9"
        active-text-color="#409eff"
      >
        <el-sub-menu index="/">
          <template #title>
            <el-icon><DataAnalysis /></el-icon>
            <span>实时仪表盘</span>
          </template>
          <el-menu-item index="/">
            <el-icon><Odometer /></el-icon>
            <span>总览</span>
          </el-menu-item>
          <el-menu-item index="/dns">
            <el-icon><Search /></el-icon>
            <span>DNS仪表盘</span>
          </el-menu-item>
        </el-sub-menu>
        <el-menu-item index="/live-sessions">
          <el-icon><Monitor /></el-icon>
          <span>实时会话</span>
        </el-menu-item>
        <el-menu-item index="/history">
          <el-icon><Search /></el-icon>
          <span>历史查询</span>
        </el-menu-item>
        <el-menu-item index="/security">
          <el-icon>
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 2L3 7v6c0 5.25 3.83 10.15 9 11 5.17-.85 9-5.75 9-11V7l-9-5z"/>
              <path d="M9 12l2 2 4-4"/>
            </svg>
          </el-icon>
          <span>安全态势</span>
        </el-menu-item>
        <el-menu-item index="/profiles">
          <el-icon><Avatar /></el-icon>
          <span>设备画像</span>
        </el-menu-item>
        <el-menu-item index="/settings">
          <el-icon><Setting /></el-icon>
          <span>系统设置</span>
        </el-menu-item>
      </el-menu>
    </el-aside>

    <!-- 主区域 -->
    <el-container>
      <!-- 顶部栏 -->
      <el-header class="layout-header">
        <div class="header-left">
          <el-tag type="success" size="small" effect="dark" v-if="wsConnected">
            <el-icon><Link /></el-icon> 实时
          </el-tag>
          <el-tag type="danger" size="small" effect="dark" v-else>
            <el-icon><WarningFilled /></el-icon> 离线
          </el-tag>
          <span class="header-title">{{ route.meta.title }}</span>
        </div>
        <div class="header-right">
          <el-tooltip content="刷新数据" placement="bottom">
            <el-button :icon="Refresh" circle @click="refreshData" />
          </el-tooltip>
        </div>
      </el-header>

      <!-- 内容区 -->
      <el-main class="layout-main">
        <slot />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import {
  Monitor, DataAnalysis, Search, Setting, Avatar, Odometer,
  Link, WarningFilled, Refresh,
} from '@element-plus/icons-vue'
import { useTrafficStore } from '@/stores/traffic'
import { useWebSocket } from '@/composables/useWebSocket'

const route = useRoute()
const store = useTrafficStore()

// WebSocket 实时数据推送到 store
const { connected: wsConnected, connect: wsConnect, disconnect: wsDisconnect } = useWebSocket(
  (data) => {
    store.overview = data
  }
)

let refreshTimer: ReturnType<typeof setInterval> | null = null
let conversationTimer: ReturnType<typeof setInterval> | null = null

function refreshData() {
  store.refreshAll()
}

onMounted(() => {
  store.refreshAll()
  wsConnect()
  // 每 10s 刷新概览和协议/Top数据
  refreshTimer = setInterval(() => store.refreshAll(), 10000)
  // 每 30s 刷新会话列表
  conversationTimer = setInterval(() => store.refreshConversations(), 30000)
})

onUnmounted(() => {
  wsDisconnect()
  if (refreshTimer) clearInterval(refreshTimer)
  if (conversationTimer) clearInterval(conversationTimer)
})
</script>

<style scoped>
.layout-container {
  height: 100vh;
}
.layout-aside {
  background-color: #304156;
  overflow-y: auto;
}
.logo {
  height: 60px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  color: #fff;
  font-size: 20px;
  font-weight: 700;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}
.layout-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: #fff;
  border-bottom: 1px solid #e4e7ed;
  padding: 0 20px;
  height: 50px;
}
.header-left {
  display: flex;
  align-items: center;
  gap: 12px;
}
.header-title {
  font-size: 15px;
  font-weight: 600;
  color: #303133;
}
.header-right {
  display: flex;
  align-items: center;
  gap: 8px;
}
.layout-main {
  background: #f5f7fa;
  padding: 16px;
  overflow-y: auto;
}
</style>
