<template>
  <div class="live-sessions">
    <!-- 加载状态 -->
    <el-skeleton :rows="3" animated v-if="loading" />

    <!-- 错误提示 -->
    <el-alert
      v-if="error"
      :title="error"
      type="error"
      show-icon
      closable
      style="margin-bottom: 16px"
      @close="error = ''"
    />

    <!-- PCAP 文件下载面板 -->
    <el-card shadow="hover" class="pcap-download-panel" style="margin-top: 16px">
      <template #header>
        <div class="capture-header">
          <span>
            <el-icon><Download /></el-icon>
            PCAP 录制与下载
          </span>
        </div>
      </template>

      <div class="pcap-controls">
        <span class="pcap-control-label">录制网口</span>
        <el-select
          v-model="pcapInterfaces"
          multiple
          collapse-tags
          collapse-tags-tooltip
          placeholder="选择网卡 (多选)"
          style="width: 220px"
          size="small"
          :disabled="pcapRecording"
        >
          <el-option
            v-for="iface in interfaces"
            :key="iface.name"
            :label="iface.name + (iface.ip ? ` (${iface.ip})` : '')"
            :value="iface.name"
          />
        </el-select>

        <span class="pcap-control-label" style="margin-left: 16px">BPF 过滤</span>
        <el-input
          v-model="pcapBpfFilter"
          placeholder="例: port 80 or port 443"
          clearable
          size="small"
          style="width: 200px"
          :disabled="pcapRecording"
        />

        <el-button
          :type="pcapRecording ? 'danger' : 'success'"
          :icon="pcapRecording ? VideoPause : VideoPlay"
          :loading="pcapRecordingLoading"
          size="small"
          style="margin-left: 16px"
          @click="togglePcapRecording"
        >
          {{ pcapRecording ? '停止录制' : '开始录制' }}
        </el-button>
        <el-button size="small" :icon="Refresh" @click="fetchPcapFiles" style="margin-left: 8px">
          刷新列表
        </el-button>
      </div>

      <div v-if="pcapFilesLoading" class="pcap-loading">
        <el-skeleton :rows="2" animated />
      </div>

      <div v-else-if="pcapFiles.length === 0" class="pcap-empty">
        <el-empty description="暂无 PCAP 文件" :image-size="40" />
      </div>

      <el-table
        v-else
        :data="pcapFilesDisplay"
        style="width: 100%"
        size="small"
        stripe
      >
        <el-table-column prop="name" label="文件名" min-width="300" />
        <el-table-column prop="size" label="大小" width="120" align="right" />
        <el-table-column prop="modified" label="修改时间" width="180" />
        <el-table-column label="操作" width="180" align="center">
          <template #default="{ row }">
            <el-button
              type="primary"
              size="small"
              :icon="Download"
              @click="downloadPcap(row.name)"
            >
              下载
            </el-button>
            <el-button
              type="danger"
              size="small"
              :icon="Delete"
              @click="deletePcap(row.name)"
            >
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 实时会话列表 -->
    <el-row :gutter="16" style="margin-top: 16px">
      <el-col :span="24">
        <LiveTable :data="store.liveSessions" :showFilter="true" />
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useTrafficStore } from '@/stores/traffic'
import { VideoPlay, VideoPause, Refresh, Download, Search, Delete } from '@element-plus/icons-vue'
import LiveTable from '@/components/LiveTable.vue'
import axios from 'axios'

interface InterfaceInfo {
  name: string
  ip: string
  mac: string
  is_loopback: boolean
  is_up: boolean
}

const store = useTrafficStore()
const loading = ref(false)
const error = ref('')

const interfaces = ref<InterfaceInfo[]>([])
// PCAP 录制参数
const pcapInterfaces = ref<string[]>([])
const pcapBpfFilter = ref('')
let conversationTimer: ReturnType<typeof setInterval> | null = null

// PCAP 录制控制
const pcapRecording = ref(false)
const pcapRecordingLoading = ref(false)

async function togglePcapRecording() {
  pcapRecordingLoading.value = true
  try {
    if (pcapRecording.value) {
      const { data } = await axios.post('/api/v1/capture/recording/stop')
      pcapRecording.value = data.recording
    } else {
      const ifaces = pcapInterfaces.value
      const { data } = await axios.post('/api/v1/capture/recording/start', {
        interface: ifaces.join(','),
        bpf_filter: pcapBpfFilter.value,
      })
      pcapRecording.value = data.recording
    }
  } catch (e: any) {
    error.value = pcapRecording.value ? '停止录制失败' : '开启录制失败'
  } finally {
    pcapRecordingLoading.value = false
  }
}

// PCAP 文件下载
async function fetchPcapRecordingStatus() {
  try {
    const { data } = await axios.get('/api/v1/capture/recording/status')
    pcapRecording.value = data.recording
  } catch (_e) {
    // 静默
  }
}
interface PcapFileInfo {
  name: string
  size_bytes: number
  modified: string
}

const pcapFiles = ref<PcapFileInfo[]>([])
const pcapFilesLoading = ref(false)

async function fetchInterfaces() {
  try {
    const { data } = await axios.get<InterfaceInfo[]>('/api/v1/capture/interfaces')
    interfaces.value = data.filter((i) => !i.is_loopback)
    // 默认选中第一个（用于 PCAP 录制）
    if (pcapInterfaces.value.length === 0 && interfaces.value.length > 0) {
      pcapInterfaces.value = [interfaces.value[0].name]
    }
  } catch (e: any) {
    error.value = '获取网卡列表失败: ' + (e?.message || '未知错误')
  }
}

function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i]
}

function formatTime(isoStr: string): string {
  const d = new Date(isoStr)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

// 在表格中显示格式化后的大小和时间
const pcapFilesDisplay = computed(() =>
  pcapFiles.value.map((f) => ({
    ...f,
    size: formatFileSize(f.size_bytes),
    modified: formatTime(f.modified),
  }))
)

async function fetchPcapFiles() {
  pcapFilesLoading.value = true
  try {
    const { data } = await axios.get<{ name: string; size_bytes: number; modified: string }[]>(
      '/api/v1/capture/pcap-files'
    )
    pcapFiles.value = data
  } catch (e: any) {
    // 静默处理
  } finally {
    pcapFilesLoading.value = false
  }
}

function downloadPcap(filename: string) {
  const a = document.createElement('a')
  a.href = `/api/v1/capture/pcap-files/${encodeURIComponent(filename)}`
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
}

async function deletePcap(filename: string) {
  try {
    await axios.delete(`/api/v1/capture/pcap-files/${encodeURIComponent(filename)}`)
    // 刷新文件列表
    await fetchPcapFiles()
  } catch (e: any) {
    error.value = '删除失败: ' + (e?.response?.data?.detail || e?.message || '未知错误')
  }
}

onMounted(async () => {
  loading.value = true
  try {
    await Promise.all([
      fetchInterfaces(),
      store.refreshLiveSessions(),
      fetchPcapFiles(),
      fetchPcapRecordingStatus(),
    ])
    // 默认选择第一个网卡用于 PCAP 录制
    if (pcapInterfaces.value.length === 0 && interfaces.value.length > 0) {
      pcapInterfaces.value = [interfaces.value[0].name]
    }
  } finally {
    loading.value = false
  }

  // 每 2s 刷新实时会话（从内存中读取，无需入库）
  conversationTimer = setInterval(() => store.refreshLiveSessions(), 2000)
})

onUnmounted(() => {
  if (conversationTimer) clearInterval(conversationTimer)
})
</script>

<style scoped>
.live-sessions {
  max-width: 1400px;
  margin: 0 auto;
}

.capture-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-weight: 600;
}

.capture-header span {
  display: flex;
  align-items: center;
  gap: 6px;
}

.capture-stats {
  display: flex;
  gap: 16px;
  justify-content: flex-end;
  flex-wrap: wrap;
}

.stat-item {
  text-align: center;
}

.stat-label {
  display: block;
  font-size: 12px;
  color: #909399;
  margin-bottom: 2px;
  white-space: nowrap;
}

.stat-value {
  display: block;
  font-size: 18px;
  font-weight: 600;
  color: #303133;
}

:deep(.el-statistic) {
  text-align: center;
}

:deep(.el-statistic__head) {
  font-size: 12px;
  color: #909399;
  margin-bottom: 2px;
}

:deep(.el-statistic__content) {
  font-size: 18px;
  font-weight: 600;
  color: #303133;
}

.pcap-download-panel {
  margin-bottom: 8px;
}

.pcap-controls {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 4px;
}
.pcap-control-label {
  font-size: 12px;
  color: #606266;
  margin-right: 4px;
  white-space: nowrap;
}

.pcap-download-panel :deep(.el-table__header th) {
  background-color: #f5f7fa;
  font-weight: 600;
}

.pcap-loading {
  padding: 20px;
}

.pcap-empty {
  padding: 4px 0;
}
.pcap-empty :deep(.el-empty__image) {
  width: 60px;
}
.pcap-empty :deep(.el-empty__image img) {
  width: 40px;
  object-fit: contain;
}
</style>
