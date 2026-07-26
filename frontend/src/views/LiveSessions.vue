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

    <!-- 抓包控制面板 -->
    <el-card shadow="hover" class="capture-panel">
      <template #header>
        <div class="capture-header">
          <span>
            <el-icon><Monitor /></el-icon>
            抓包控制
          </span>
          <el-tag
            :type="captureStatus.running ? 'success' : 'danger'"
            size="small"
            effect="dark"
          >
            {{ captureStatus.running ? '● 运行中' : '● 已停止' }}
          </el-tag>
        </div>
      </template>

      <el-row :gutter="16" align="middle">
        <!-- 网卡选择 -->
        <el-col :span="5">
          <el-form-item label="网卡接口">
            <el-select
              v-model="selectedInterfaces"
              multiple
              collapse-tags
              collapse-tags-tooltip
              placeholder="选择网卡 (多选)"
              style="width: 100%"
              :disabled="captureStatus.running"
            >
              <el-option
                v-for="iface in interfaces"
                :key="iface.name"
                :label="iface.name + (iface.ip ? ` (${iface.ip})` : '')"
                :value="iface.name"
              />
            </el-select>
          </el-form-item>
        </el-col>

        <!-- 启动/停止按钮 -->
        <el-col :span="6">
          <el-form-item label=" ">
            <el-button
              type="primary"
              :icon="VideoPlay"
              :loading="starting"
              :disabled="captureStatus.running || selectedInterfaces.length === 0"
              @click="startCapture"
            >
              开始抓包
            </el-button>
          </el-form-item>
        </el-col>
        <el-col :span="4">
          <el-form-item label=" ">
            <el-button
              type="danger"
              :icon="VideoPause"
              :loading="stopping"
              :disabled="!captureStatus.running"
              @click="stopCapture"
            >
              停止抓包
            </el-button>
          </el-form-item>
        </el-col>

        <!-- 统计信息 -->
        <el-col :span="6">
          <div class="capture-stats">
            <div class="stat-item">
              <span class="stat-label">已处理包</span>
              <span class="stat-value">{{ captureStatus.packets_processed }}</span>
            </div>
            <div class="stat-item">
              <span class="stat-label">活跃流</span>
              <span class="stat-value">{{ captureStatus.active_flows }}</span>
            </div>
            <div class="stat-item">
              <span class="stat-label">运行时长</span>
              <span class="stat-value">{{ formatUptime(captureStatus.uptime_seconds) }}</span>
            </div>
            <div class="stat-item">
              <span class="stat-label">DPI</span>
              <span class="stat-value" :style="{ color: captureStatus.dpi_available ? '#67c23a' : '#e6a23c' }">
                {{ captureStatus.dpi_available ? 'nDPI' : '回退' }}
              </span>
            </div>
          </div>
        </el-col>
      </el-row>

      <!-- 网卡刷新按钮 -->
      <el-row style="margin-top: 8px">
        <el-col>
          <el-button size="small" :icon="Refresh" @click="fetchInterfaces">
            刷新网卡列表
          </el-button>
        </el-col>
      </el-row>
    </el-card>

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

      <el-row :gutter="16" align="middle" style="margin-bottom: 12px">
        <el-col :span="5">
          <el-form-item label="录制网口" style="margin-bottom: 0">
            <el-select
              v-model="pcapInterfaces"
              multiple
              collapse-tags
              collapse-tags-tooltip
              placeholder="选择网卡 (多选)"
              style="width: 100%"
              :disabled="pcapRecording"
            >
              <el-option
                v-for="iface in interfaces"
                :key="iface.name"
                :label="iface.name + (iface.ip ? ` (${iface.ip})` : '')"
                :value="iface.name"
              />
            </el-select>
          </el-form-item>
        </el-col>
        <el-col :span="6">
          <el-form-item label="BPF 过滤" style="margin-bottom: 0">
            <el-input
              v-model="pcapBpfFilter"
              placeholder="例: port 80 or port 443"
              clearable
              :disabled="pcapRecording"
            />
          </el-form-item>
        </el-col>
        <el-col :span="4">
          <el-button
            :type="pcapRecording ? 'danger' : 'success'"
            :icon="pcapRecording ? VideoPause : VideoPlay"
            :loading="pcapRecordingLoading"
            @click="togglePcapRecording"
          >
            {{ pcapRecording ? '停止录制' : '开始录制' }}
          </el-button>
        </el-col>
        <el-col :span="3">
          <el-button size="default" :icon="Refresh" @click="fetchPcapFiles">
            刷新文件列表
          </el-button>
        </el-col>
      </el-row>

      <el-alert
        v-if="pcapRecording"
        title="PCAP 录制已开启，正在实时保存数据包..."
        type="warning"
        show-icon
        :closable="false"
        style="margin-bottom: 12px"
      />

      <div v-if="pcapFilesLoading" class="pcap-loading">
        <el-skeleton :rows="2" animated />
      </div>

      <div v-else-if="pcapFiles.length === 0" class="pcap-empty">
        <el-empty description="暂无 PCAP 文件" :image-size="80" />
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
import { ref, computed, onMounted, onUnmounted, reactive } from 'vue'
import { useTrafficStore } from '@/stores/traffic'
import { Monitor, VideoPlay, VideoPause, Refresh, Download, Search, Delete } from '@element-plus/icons-vue'
import LiveTable from '@/components/LiveTable.vue'
import axios from 'axios'

interface InterfaceInfo {
  name: string
  ip: string
  mac: string
  is_loopback: boolean
  is_up: boolean
}

interface CaptureStatus {
  running: boolean
  interface: string
  pcap_file: string
  packets_processed: number
  uptime_seconds: number
  active_flows: number
  dpi_available: boolean
  pcap_output_enabled: boolean
}

const store = useTrafficStore()
const loading = ref(false)
const error = ref('')
const starting = ref(false)
const stopping = ref(false)

// 抓包状态
const captureStatus = reactive<CaptureStatus>({
  running: false,
  interface: '',
  pcap_file: '',
  packets_processed: 0,
  uptime_seconds: 0,
  active_flows: 0,
  dpi_available: false,
  pcap_output_enabled: false,
})

const interfaces = ref<InterfaceInfo[]>([])
const selectedInterfaces = ref<string[]>([])
// PCAP 录制参数
const pcapInterfaces = ref<string[]>([])
const pcapBpfFilter = ref('')
let statusTimer: ReturnType<typeof setInterval> | null = null
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
      const ifaces = pcapInterfaces.value.length > 0 ? pcapInterfaces.value : selectedInterfaces.value
      const { data } = await axios.post('/api/v1/capture/recording/start', {
        interface: ifaces.join(','),
        bpf_filter: pcapBpfFilter.value,
      })
      pcapRecording.value = data.recording
      // 如果网卡变了，同步更新抓包控制面板
      if (ifaces.length > 0 && ifaces.join(',') !== selectedInterfaces.value.join(',')) {
        selectedInterfaces.value = ifaces
        await fetchCaptureStatus()
      }
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

function formatUptime(seconds: number): string {
  if (seconds <= 0) return '0s'
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = Math.floor(seconds % 60)
  if (h > 0) return `${h}h${m}m${s}s`
  if (m > 0) return `${m}m${s}s`
  return `${s}s`
}

async function fetchCaptureStatus() {
  try {
    const { data } = await axios.get<CaptureStatus>('/api/v1/capture/status')
    Object.assign(captureStatus, data)
  } catch (e: any) {
    // 静默
  }
}

async function fetchInterfaces() {
  try {
    const { data } = await axios.get<InterfaceInfo[]>('/api/v1/capture/interfaces')
    interfaces.value = data.filter((i) => !i.is_loopback)
    // 如果当前选中的网卡不在列表中，清空
    // 如果当前选中的网卡不在列表中，清理无效项
    const validNames = new Set(data.map((i: InterfaceInfo) => i.name))
    selectedInterfaces.value = selectedInterfaces.value.filter((n: string) => validNames.has(n))
  } catch (e: any) {
    error.value = '获取网卡列表失败: ' + (e?.message || '未知错误')
  }
}

async function startCapture() {
  if (selectedInterfaces.value.length === 0) return
  starting.value = true
  error.value = ''
  try {
    await axios.post('/api/v1/capture/start', {
      interface: selectedInterfaces.value.join(','),
    })
    await fetchCaptureStatus()
  } catch (e: any) {
    error.value = '启动抓包失败: ' + (e?.response?.data?.detail || e?.message || '未知错误')
  } finally {
    starting.value = false
  }
}

async function stopCapture() {
  stopping.value = true
  error.value = ''
  try {
    await axios.post('/api/v1/capture/stop')
    await fetchCaptureStatus()
  } catch (e: any) {
    error.value = '停止抓包失败: ' + (e?.message || '未知错误')
  } finally {
    stopping.value = false
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
      fetchCaptureStatus(),
      fetchInterfaces(),
      store.refreshLiveSessions(),
      fetchPcapFiles(),
      fetchPcapRecordingStatus(),
    ])
    // 如果当前有运行中的抓包，选择对应的网卡
    if (captureStatus.interface) {
      selectedInterfaces.value = captureStatus.interface.split(',')
      pcapInterfaces.value = captureStatus.interface.split(',')
    } else if (interfaces.value.length > 0) {
      selectedInterfaces.value = [interfaces.value[0].name]
      pcapInterfaces.value = [interfaces.value[0].name]
    }
  } finally {
    loading.value = false
  }

  // 每 2s 刷新抓包状态
  statusTimer = setInterval(fetchCaptureStatus, 2000)
  // 每 2s 刷新实时会话（从内存中读取，无需入库）
  conversationTimer = setInterval(() => store.refreshLiveSessions(), 2000)
})

onUnmounted(() => {
  if (statusTimer) clearInterval(statusTimer)
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

.pcap-download-panel :deep(.el-table__header th) {
  background-color: #f5f7fa;
  font-weight: 600;
}

.pcap-loading {
  padding: 20px;
}

.pcap-empty {
  padding: 10px 0;
}
</style>
