<template>
  <div class="settings-page">
    <!-- 系统状态 -->
    <el-card shadow="hover" style="margin-bottom: 16px">
      <template #header><span class="card-title">系统状态</span></template>
      <el-descriptions :column="3" border size="small" v-if="status">
        <el-descriptions-item label="运行状态">
          <el-tag :type="status.status === 'running' ? 'success' : 'danger'" size="small">
            {{ status.status === 'running' ? '运行中' : '异常' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="运行时间">{{ formatUptime(status.uptime_seconds) }}</el-descriptions-item>
        <el-descriptions-item label="API 版本">v{{ status.version }}</el-descriptions-item>
        <el-descriptions-item label="存储后端">
          <el-tag size="small">{{ status.storage_backend.toUpperCase() }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="采集器">
          <el-tag :type="status.collector_running ? 'success' : 'info'" size="small">
            {{ status.collector_running ? '运行中' : '未启动' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="缓存流数">{{ status.flows_cached }}</el-descriptions-item>
      </el-descriptions>
      <el-skeleton :rows="3" animated v-else />
    </el-card>

    <!-- 数据缓存 -->
    <el-card shadow="hover" style="margin-bottom: 16px">
      <template #header><span class="card-title">数据缓存</span></template>
      <div style="margin-bottom:12px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
        <div style="font-size:13px">
          缓存数据包
          <el-tag size="small" :type="cacheEnabled ? 'success' : 'info'" style="margin-left:8px">
            {{ cacheEnabled ? '已开启' : '已关闭' }}
          </el-tag>
          <div style="color:#909399;font-size:11px;margin-top:4px">
            开启后系统会缓存经过的原始数据包（pcap），供报文查看与流追踪使用
          </div>
        </div>
        <el-switch v-model="cacheEnabled" :loading="cacheSaving" @change="saveCacheEnabled" />
      </div>
      <el-divider style="margin:4px 0 12px" />
      <el-skeleton :rows="4" animated v-if="!storageInfo" />
      <template v-else>
        <div style="margin-bottom:10px;font-size:12px;color:#909399">
          挂载点：<code>{{ storageInfo.mount_point }}</code>
          <span style="margin-left:16px">数据目录：<code>{{ storageInfo.data_path }}</code></span>
        </div>
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item label="总容量">{{ formatBytes(storageInfo.disk_total) }}</el-descriptions-item>
          <el-descriptions-item label="已用">{{ formatBytes(storageInfo.disk_used) }}</el-descriptions-item>
          <el-descriptions-item label="剩余">{{ formatBytes(storageInfo.disk_free) }}</el-descriptions-item>
          <el-descriptions-item label="使用率">
            <el-progress :percentage="storageInfo.disk_usage_percent" :stroke-width="14"
              :status="storageInfo.disk_usage_percent > storageInfo.pcap_storage_threshold ? 'exception' : ''" />
          </el-descriptions-item>
          <el-descriptions-item label="数据实际占用">
            {{ formatBytes(storageInfo.data_size_bytes) }}
            <span style="color:#909399;font-size:11px;margin-left:4px">
              (占挂载点 {{ (storageInfo.data_size_bytes / storageInfo.disk_total * 100).toFixed(2) }}%)
            </span>
          </el-descriptions-item>
          <el-descriptions-item label="pcap 文件数 / 大小">
            {{ storageInfo.pcap_files }} 个 / {{ formatBytes(storageInfo.pcap_size_bytes) }}
          </el-descriptions-item>
          <el-descriptions-item label="清理阈值">
            <el-input-number v-model="cleanupThreshold" :min="10" :max="99" size="small" style="width: 100px" />
            <el-button size="small" style="margin-left: 6px" type="primary" @click="saveCleanupThreshold">保存</el-button>
          </el-descriptions-item>
          <el-descriptions-item label="手动清理">
            <el-button size="small" :loading="cleaning" @click="triggerCleanup" :disabled="storageInfo.pcap_files === 0">
              {{ cleaning ? '清理中...' : '清理旧 pcap' }}
            </el-button>
          </el-descriptions-item>
        </el-descriptions>
      </template>
    </el-card>

    <!-- 存储配置 -->
    <el-card shadow="hover" style="margin-bottom: 16px">
      <template #header><span class="card-title">存储配置</span></template>
      <el-form label-width="120px" size="small">
        <el-form-item label="当前后端">
          <el-tag size="small">{{ status?.storage_backend?.toUpperCase() || 'SQLite' }}</el-tag>
        </el-form-item>
        <el-form-item label="切换后端">
          <el-radio-group v-model="targetBackend" disabled>
            <el-radio value="sqlite">SQLite（默认）</el-radio>
            <el-radio value="influxdb">InfluxDB</el-radio>
            <el-radio value="clickhouse">ClickHouse</el-radio>
          </el-radio-group>
          <div style="color: #909399; font-size: 12px; margin-top: 4px">
            ⚡ 切换后需要重启 API 服务生效，并在后端 config.yaml 中设置对应连接信息
          </div>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- 采集配置 -->
    <el-card shadow="hover" style="margin-bottom: 16px">
      <template #header><span class="card-title">采集配置</span></template>
      <el-form label-width="120px" size="small">
        <el-form-item label="采集网口">
          <el-select v-model="selectedInterfaces" multiple collapse-tags collapse-tags-tooltip
            placeholder="选择要抓包的网卡（可多选）" style="width: 280px"
            :loading="interfacesLoading" :disabled="status?.collector_running">
            <el-option
              v-for="iface in interfaces"
              :key="iface.name"
              :label="iface.name + (iface.ip ? ' (' + iface.ip + ')' : '') + (iface.is_loopback ? ' [回环]' : '')"
              :value="iface.name"
            />
          </el-select>
          <el-tag size="small" :type="status?.collector_running ? 'success' : 'info'" style="margin-left: 8px">
            {{ status?.collector_running ? '抓包中' : '未抓包' }}
          </el-tag>
          <span v-if="status?.collector_running && currentInterface" style="color:#909399;font-size:12px;margin-left:8px">
            当前: {{ currentInterface }}
          </span>
        </el-form-item>
        <el-form-item label=" ">
          <el-button type="success" size="small" @click="startCapture" :disabled="status?.collector_running || selectedInterfaces.length === 0">
            启动抓包
          </el-button>
          <el-button type="danger" size="small" @click="stopCapture" :disabled="!status?.collector_running">
            停止抓包
          </el-button>
          <el-button size="small" @click="fetchInterfaces" :loading="interfacesLoading">
            刷新网口
          </el-button>
        </el-form-item>
        <el-form-item label="nDPI 状态">
          <el-tag type="success" size="small" v-if="ndpiAvailable">已加载</el-tag>
          <el-tag type="warning" size="small" v-else>未加载（端口回退）</el-tag>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- IPFIX / NetFlow v10 导出 -->
    <el-card shadow="hover" style="margin-bottom: 16px">
      <template #header><span class="card-title">IPFIX (NetFlow v10) 导出</span></template>
      <el-form label-width="140px" size="small">
        <el-form-item label="导出状态">
          <el-tag :type="ipfixRunning ? 'success' : 'info'" size="small">
            {{ ipfixRunning ? (ipfixEnabled ? '运行中' : '未启用') : '已停止' }}
          </el-tag>
          <span style="margin-left: 8px; color: #909399; font-size: 12px" v-if="ipfixRunning">
            {{ ipfixHost }}:{{ ipfixPort }}
          </span>
        </el-form-item>
        <el-form-item label="Collector 地址">
          <el-input v-model="ipfixHost" placeholder="127.0.0.1" style="width: 200px" />
        </el-form-item>
        <el-form-item label="Collector 端口">
          <el-input-number v-model="ipfixPort" :min="1" :max="65535" size="small" />
        </el-form-item>
        <el-form-item label=" ">
          <el-button type="success" size="small" @click="startIpfix" :disabled="ipfixRunning">
            启动导出
          </el-button>
          <el-button type="danger" size="small" @click="stopIpfix" :disabled="!ipfixRunning">
            停止导出
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- GeoIP 地理位置数据库 -->
    <el-card shadow="hover" style="margin-bottom: 16px">
      <template #header>
        <div class="geo-header">
          <span class="card-title">GeoIP 地理位置数据库</span>
          <div>
            <el-button
              type="primary"
              size="small"
              :icon="Refresh"
              :loading="geoUpdating"
              :disabled="geoUpdating || !geoConfig.has_account"
              @click="triggerGeoUpdate"
            >
              {{ geoUpdating ? '更新中...' : '在线更新' }}
            </el-button>
          </div>
        </div>
      </template>

      <!-- GeoIP 账号配置 -->
      <el-form inline size="small" style="margin-bottom: 12px">
        <el-form-item label="Account ID">
          <el-input v-model="geoAccountId" placeholder="MaxMind Account ID" style="width: 160px" />
        </el-form-item>
        <el-form-item label="License Key">
          <el-input v-model="geoLicenseKey" :type="showLicenseKey ? 'text' : 'password'" placeholder="MaxMind License Key" style="width: 200px">
            <template #append>
              <el-button @click="showLicenseKey = !showLicenseKey" size="small">
                {{ showLicenseKey ? '隐藏' : '显示' }}
              </el-button>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="success" size="small" @click="saveGeoConfig">保存</el-button>
        </el-form-item>
      </el-form>

      <el-descriptions :column="2" border size="small" style="margin-bottom: 12px">
        <el-descriptions-item label="解析器状态" :span="2">
          <el-tag :type="geoStatus.available ? 'success' : 'warning'" size="small">
            {{ geoStatus.available ? '已就绪' : '未就绪' }}
          </el-tag>
          <span v-if="!geoStatus.available" style="color:#909399;font-size:12px;margin-left:8px">
            请上传或在线更新 GeoLite2 数据库文件
          </span>
        </el-descriptions-item>
        <el-descriptions-item label="MaxMind 账号">
          <el-tag :type="geoConfig.has_account ? 'success' : 'info'" size="small">
            {{ geoConfig.has_account ? '已配置' : '未配置' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="自动更新">
          <el-tag :type="geoStatus.auto_update ? 'success' : 'info'" size="small">
            {{ geoStatus.auto_update ? `每 ${geoStatus.update_interval_days} 天` : '已禁用' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="最近更新">
          {{ geoStatus.last_update_time ? formatTime(geoStatus.last_update_time) : '从未更新' }}
        </el-descriptions-item>
      </el-descriptions>

      <!-- 数据库文件列表 -->
      <el-table :data="geoStatus.files" size="small" stripe style="width:100%;margin-bottom:12px">
        <el-table-column prop="edition" label="数据库" width="180" />
        <el-table-column label="状态" width="70">
          <template #default="{ row }">
            <el-tag :type="row.exists ? 'success' : 'danger'" size="small">
              {{ row.exists ? '存在' : '缺失' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="大小" width="100" align="right">
          <template #default="{ row }">
            {{ row.exists ? formatBytes(row.size_bytes) : '-' }}
          </template>
        </el-table-column>
        <el-table-column label="时效" width="100">
          <template #default="{ row }">
            <span v-if="row.exists" :style="{ color: row.age_days > 7 ? '#e6a23c' : '#67c23a' }">
              {{ row.age_days.toFixed(1) }} 天前
            </span>
            <span v-else>-</span>
          </template>
        </el-table-column>
        <el-table-column label="路径" min-width="200">
          <template #default="{ row }">
            <code style="font-size:11px;word-break:break-all">{{ row.path }}</code>
          </template>
        </el-table-column>
      </el-table>

      <!-- 上传 / 管理 -->
      <el-row :gutter="16">
        <el-col :span="12">
          <el-upload
            :http-request="handleUpload"
            :show-file-list="false"
            :disabled="uploading"
          >
            <el-button type="primary" size="small" :loading="uploading">
              {{ uploading ? '上传中...' : '上传数据库文件' }}
            </el-button>
            <template #tip>
              <div style="color:#909399;font-size:11px;margin-top:4px">支持 .mmdb 和 .tar.gz 文件</div>
            </template>
          </el-upload>
        </el-col>
        <el-col :span="12" style="text-align:right">
          <el-button size="small" @click="fetchGeoDatabases">刷新文件列表</el-button>
        </el-col>
      </el-row>

      <!-- 已上传文件列表 -->
      <el-table v-if="dbFiles.length > 0" :data="dbFiles" size="small" stripe style="width:100%;margin-top:12px">
        <el-table-column prop="name" label="文件名" min-width="200" />
        <el-table-column prop="size_display" label="大小" width="100" align="right" />
        <el-table-column label="修改时间" width="160">
          <template #default="{ row }">
            {{ formatTime(row.modified) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="80" align="center">
          <template #default="{ row }">
            <el-button type="danger" size="small" link @click="confirmDelete(row.name)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 高级功能 -->
    <el-card shadow="hover">
      <template #header><span class="card-title">高级功能</span></template>
      <el-descriptions :column="1" border size="small">
        <el-descriptions-item label="pcap 输出">
          <el-tag :type="pcapEnabled ? 'success' : 'info'" size="small">
            {{ pcapEnabled ? '已启用 (captures/)' : '未启用' }}
          </el-tag>
          <el-button v-if="pcapEnabled" link type="primary" size="small" style="margin-left: 8px">
            查看 pcap 文件
          </el-button>
        </el-descriptions-item>
        <el-descriptions-item label="TLS Key Log">
          <el-tag :type="tlsKeylogAvailable ? 'success' : 'info'" size="small">
            {{ tlsKeylogAvailable ? `${tlsKeyCount} 条密钥` : '未配置' }}
          </el-tag>
          <div style="font-size: 12px; color: #909399; margin-top: 4px" v-if="!tlsKeylogAvailable">
            设置 SSLKEYLOGFILE 环境变量可解密 TLS 流量
          </div>
        </el-descriptions-item>
        <el-descriptions-item label="tcpdump 命令">
          <code style="font-size: 12px; background: #f5f7fa; padding: 4px 8px; border-radius: 4px">
            tcpdump -i eth0 -w capture.pcap
          </code>
          <div style="font-size: 12px; color: #909399; margin-top: 4px">
            生成的 pcap 文件可直接用 Wireshark 打开分析
          </div>
        </el-descriptions-item>
      </el-descriptions>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import axios from 'axios'
import { fetchSystemStatus, fetchGeoConfig, updateGeoConfig, fetchGeoDatabases, uploadGeoDatabase, deleteGeoDatabase, triggerGeoUpdate as apiTriggerGeoUpdate } from '@/services/api'
import { Refresh } from '@element-plus/icons-vue'
import type { SystemStatus, GeoConfigInfo, GeoUpdateStatus } from '@/types'
import { ElMessage, ElMessageBox } from 'element-plus'

const status = ref<SystemStatus | null>(null)
const targetBackend = ref('sqlite')

// ── 采集网口配置 ────────────────────────────────────
const interfaces = ref<any[]>([])
const selectedInterfaces = ref<string[]>([])
const currentInterface = ref('')
const interfacesLoading = ref(false)

async function fetchInterfaces() {
  interfacesLoading.value = true
  try {
    const { data } = await axios.get('/api/v1/capture/interfaces')
    interfaces.value = (data || []).filter((i: any) => !i.is_loopback)
    // 清理已失效的选中项
    const validNames = new Set(interfaces.value.map((i: any) => i.name))
    selectedInterfaces.value = selectedInterfaces.value.filter((n) => validNames.has(n))
    // 默认选中第一个
    if (selectedInterfaces.value.length === 0 && interfaces.value.length > 0) {
      selectedInterfaces.value = [interfaces.value[0].name]
    }
  } catch {
    interfaces.value = []
  }
  interfacesLoading.value = false
}

async function startCapture() {
  if (selectedInterfaces.value.length === 0) {
    ElMessage.warning('请先选择采集网口')
    return
  }
  try {
    const { data } = await axios.post('/api/v1/capture/start', { interface: selectedInterfaces.value.join(',') })
    ElMessage.success(data.message || '抓包已启动')
    currentInterface.value = selectedInterfaces.value.join(',')
    await refreshStatus()
  } catch (e: any) {
    ElMessage.error('启动抓包失败: ' + (e?.response?.data?.detail || e?.message))
  }
}

async function stopCapture() {
  try {
    const { data } = await axios.post('/api/v1/capture/stop')
    ElMessage.success(data.message || '抓包已停止')
    currentInterface.value = ''
    await refreshStatus()
  } catch (e: any) {
    ElMessage.error('停止抓包失败: ' + (e?.response?.data?.detail || e?.message))
  }
}

async function refreshStatus() {
  try {
    status.value = await fetchSystemStatus()
    targetBackend.value = status.value.storage_backend
    currentInterface.value = (status.value as any)?.interface || ''
    // 同步当前抓包网口到选择器
    if (currentInterface.value) {
      selectedInterfaces.value = currentInterface.value.split(',')
    }
  } catch { /* ignore */ }
}

const ndpiAvailable = ref(false)
const pcapEnabled = ref(false)
const tlsKeylogAvailable = ref(false)
const tlsKeyCount = ref(0)
const geoUpdating = ref(false)

// ── 数据缓存 ────────────────────────────────────────
const storageInfo = ref<any>(null)
const cacheEnabled = ref(false)
const cacheSaving = ref(false)
const cleanupThreshold = ref(90)
const cleaning = ref(false)

async function fetchStorageInfo() {
  try {
    const { data } = await axios.get('/api/v1/system/storage')
    storageInfo.value = data
    cleanupThreshold.value = data.pcap_storage_threshold
  } catch { /* ignore */ }
  try {
    const { data } = await axios.get('/api/v1/system/pcap/config')
    cacheEnabled.value = data.enabled ?? true
  } catch { /* ignore */ }
}

async function saveCacheEnabled() {
  cacheSaving.value = true
  try {
    const { data } = await axios.post('/api/v1/system/pcap/config', {
      enabled: cacheEnabled.value,
      storage_threshold_percent: cleanupThreshold.value,
    })
    ElMessage.success(data.message || (cacheEnabled.value ? '已开启数据包缓存' : '已关闭数据包缓存'))
    // 缓存开关变化后，采集流水线会重启，刷新系统状态
    await refreshStatus()
    await fetchStorageInfo()
  } catch (e: any) {
    ElMessage.error('更新缓存配置失败: ' + (e?.response?.data?.detail || e?.message))
    await fetchStorageInfo()
  }
  cacheSaving.value = false
}

async function saveCleanupThreshold() {
  try {
    const { data } = await axios.post('/api/v1/system/pcap/config', {
      enabled: cacheEnabled.value,
      storage_threshold_percent: cleanupThreshold.value,
    })
    ElMessage.success(data.message || '清理阈值已保存')
    await fetchStorageInfo()
  } catch (e: any) {
    ElMessage.error('保存阈值失败: ' + (e?.response?.data?.detail || e?.message))
  }
}

async function triggerCleanup() {
  cleaning.value = true
  try {
    await axios.post('/api/v1/system/pcap/cleanup')
    await fetchStorageInfo()
  } catch { /* ignore */ }
  cleaning.value = false
}

// GeoIP 配置
const geoConfig = reactive<GeoConfigInfo>({
  account_id: '', license_key: '', has_account: false, db_dir: '', db_files: [],
})
const geoAccountId = ref('')
const geoLicenseKey = ref('')
const showLicenseKey = ref(false)
const dbFiles = ref<any[]>([])
const uploading = ref(false)

// IPFIX 状态
const ipfixRunning = ref(false)
const ipfixEnabled = ref(false)
const ipfixHost = ref('127.0.0.1')
const ipfixPort = ref(4739)

async function fetchIpfixStatus() {
  try {
    const { data } = await axios.get('/api/v1/export/ipfix/status')
    ipfixRunning.value = data.running
    ipfixEnabled.value = data.enabled
    ipfixHost.value = data.host || '127.0.0.1'
    ipfixPort.value = data.port || 4739
  } catch { /* 静默 */ }
}

async function startIpfix() {
  try {
    await axios.post('/api/v1/export/ipfix/start')
    await fetchIpfixStatus()
  } catch (e: any) {
    console.error('启动 IPFIX 失败', e)
  }
}

async function stopIpfix() {
  try {
    await axios.post('/api/v1/export/ipfix/stop')
    await fetchIpfixStatus()
  } catch (e: any) {
    console.error('停止 IPFIX 失败', e)
  }
}

const geoStatus = reactive<GeoUpdateStatus>({
  available: false,
  auto_update: false,
  update_interval_days: 7,
  files: [],
  last_update_time: '',
  updating: false,
})

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = seconds % 60
  const parts = []
  if (d > 0) parts.push(`${d}天`)
  if (h > 0) parts.push(`${h}小时`)
  if (m > 0) parts.push(`${m}分`)
  parts.push(`${s}秒`)
  return parts.join(' ')
}

function formatBytes(bytes: number): string {
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`
  return `${bytes} B`
}

function formatTime(iso: string): string {
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

async function fetchGeoStatus() {
  try {
    const { data } = await axios.get<GeoUpdateStatus>('/api/v1/geo/status')
    Object.assign(geoStatus, data)
  } catch {
    // 静默
  }
}

async function fetchGeoConfigData() {
  try {
    const data = await fetchGeoConfig()
    Object.assign(geoConfig, data)
    geoAccountId.value = data.account_id
    geoLicenseKey.value = ''
  } catch {
    // 静默
  }
}

async function saveGeoConfig() {
  try {
    const result = await updateGeoConfig(geoAccountId.value, geoLicenseKey.value)
    ElMessage.success(result.message || '配置已保存')
    await fetchGeoConfigData()
    await fetchGeoStatus()
  } catch (e: any) {
    ElMessage.error('保存配置失败: ' + (e?.response?.data?.detail || e?.message))
  }
}

async function fetchGeoDatabasesList() {
  try {
    const result = await fetchGeoDatabases()
    dbFiles.value = result.files
  } catch {
    // 静默
  }
}

async function handleUpload(options: any) {
  uploading.value = true
  try {
    const result = await uploadGeoDatabase(options.file)
    ElMessage.success(result.message || '上传成功')
    await fetchGeoDatabasesList()
    await fetchGeoStatus()
  } catch (e: any) {
    ElMessage.error('上传失败: ' + (e?.response?.data?.detail || e?.message))
  } finally {
    uploading.value = false
  }
}

async function confirmDelete(filename: string) {
  try {
    await ElMessageBox.confirm(`确认删除文件 ${filename}？`, '确认删除', {
      type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消',
    })
    const result = await deleteGeoDatabase(filename)
    ElMessage.success(result.message || '删除成功')
    await fetchGeoDatabasesList()
    await fetchGeoStatus()
  } catch {
    // 取消或失败都不处理
  }
}

async function triggerGeoUpdate() {
  geoUpdating.value = true
  try {
    const result = await apiTriggerGeoUpdate()
    ElMessage.success(result.message || '更新成功')
    await fetchGeoStatus()
  } catch (e: any) {
    ElMessage.error('更新失败: ' + (e?.response?.data?.detail || e?.message))
  } finally {
    geoUpdating.value = false
  }
}

onMounted(async () => {
  await refreshStatus()
  await fetchInterfaces()

  await fetchGeoStatus()
  await fetchGeoConfigData()
  await fetchGeoDatabasesList()
  await fetchStorageInfo()
  await fetchIpfixStatus()

  // 检测 nDPI
  try {
    const resp = await fetch('/health')
    const data = await resp.json()
    ndpiAvailable.value = data?.ndpi ?? false
  } catch {
    ndpiAvailable.value = false
  }

  // 检测高级功能
  try {
    const resp = await fetch('/api/v1/system/status')
    const data = await resp.json()
    // 通过 flows_cached 和 status 间接判断
    pcapEnabled.value = data?.collector_running ?? false
  } catch {
    // ignore
  }

  // 检查是否有 TLS 相关流
  try {
    const resp = await fetch('/api/v1/traffic/conversations?size=5&l7_proto=tls')
    const data = await resp.json()
    tlsKeylogAvailable.value = data?.items?.length > 0
    tlsKeyCount.value = data?.total ?? 0
  } catch {
    // ignore
  }
})
</script>

<style scoped>
.settings-page {
  max-width: 900px;
  margin: 0 auto;
}
.card-title {
  font-weight: 600;
}

.geo-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>
