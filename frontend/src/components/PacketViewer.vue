<template>
  <el-dialog v-model="visible" :title="`报文详情 - #${flowId}`" width="95%" destroy-on-close top="2vh">
    <template v-if="loading">
      <el-skeleton :rows="6" animated />
    </template>

    <template v-else-if="error">
      <el-alert :title="error" type="warning" show-icon />
    </template>

    <template v-else>
      <!-- 包摘要 -->
      <div class="packet-summary">
        <el-tag size="small">{{ packets.length }} 个包</el-tag>
        <el-tag size="small" type="info" v-if="pcapFile">pcap: {{ pcapFilename }}</el-tag>
      </div>

      <el-table :data="packets" stripe size="small" style="width: 100%" max-height="600" @row-click="selectPacket">
        <el-table-column label="#" width="50" type="index" />
        <el-table-column label="时间" min-width="170">
          <template #default="{ row }">{{ formatTime(row.timestamp) }}</template>
        </el-table-column>
        <el-table-column label="方向" width="70">
          <template #default="{ row }">
            <span :class="row.summary.startsWith('←') ? 'dir-in' : 'dir-out'">
              {{ row.summary.startsWith('←') ? '← 入' : '→ 出' }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="协议" width="80">
          <template #default="{ row }">
            {{ row.summary.includes('TCP') ? 'TCP' : row.summary.includes('UDP') ? 'UDP' : 'IP' }}
          </template>
        </el-table-column>
        <el-table-column label="长度" width="80">
          <template #default="{ row }">{{ row.length }} B</template>
        </el-table-column>
        <el-table-column label="摘要" min-width="200">
          <template #default="{ row }">{{ row.summary }}</template>
        </el-table-column>
        <el-table-column label="操作" width="60">
          <template #default="{ row }">
            <el-link type="primary" size="small" @click.stop="selectPacket(row)">HEX</el-link>
          </template>
        </el-table-column>
      </el-table>

      <!-- 选中包的原始 HEX -->
      <el-card v-if="selectedPacket" shadow="hover" style="margin-top: 12px">
        <template #header>
          <div class="hex-header">
            <span>原始报文 ({{ selectedPacket.length }} bytes)</span>
            <el-button size="small" @click="copyHex">复制 HEX</el-button>
          </div>
        </template>
        <pre class="hex-dump"><code>{{ formatHexDump(selectedPacket.raw_hex) }}</code></pre>
      </el-card>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import axios from 'axios'

const props = defineProps<{
  visible: boolean
  flowId: number
  flowLabel?: string
}>()

const emit = defineEmits<{ (e: 'update:visible', v: boolean): void }>()

const loading = ref(false)
const error = ref('')
const packets = ref<any[]>([])
const pcapFile = ref('')
const selectedPacket = ref<any>(null)

const pcapFilename = computed(() => pcapFile.value ? pcapFile.value.split('/').pop() : '')

async function fetchPackets() {
  if (!props.flowId) return
  loading.value = true
  error.value = ''
  packets.value = []
  selectedPacket.value = null
  try {
    const { data } = await axios.get(`/api/v1/traffic/flows/${props.flowId}/packets`)
    packets.value = data.packets || []
    pcapFile.value = data.pcap_file || ''
    if (packets.value.length === 0) {
      error.value = '该流没有关联的 pcap 报文数据'
    }
  } catch (e: any) {
    error.value = e?.response?.data?.detail || '获取报文失败'
  }
  loading.value = false
}

function selectPacket(row: any) {
  selectedPacket.value = selectedPacket.value?.timestamp === row.timestamp && selectedPacket.value?.length === row.length ? null : row
}

function formatTime(ts: number | string): string {
  const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts)
  return `${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}.${String(d.getMilliseconds()).padStart(3, '0')}`
}

function formatHexDump(hex: string): string {
  const lines: string[] = []
  for (let i = 0; i < hex.length; i += 64) {
    const addr = (i / 2).toString(16).padStart(8, '0')
    const hexPart = hex.slice(i, i + 64).replace(/(.{2})/g, '$1 ').trim()
    const asciiPart = hex.slice(i, i + 64).replace(/.{2}/g, (b) => {
      const c = parseInt(b, 16)
      return c >= 32 && c <= 126 ? String.fromCharCode(c) : '.'
    })
    lines.push(`${addr}  ${hexPart.padEnd(48)}  ${asciiPart}`)
  }
  return lines.join('\n')
}

function copyHex() {
  if (!selectedPacket.value?.raw_hex) return
  navigator.clipboard.writeText(selectedPacket.value.raw_hex)
}

// 监听 visible 变化自动加载
import { watch } from 'vue'
watch(() => props.visible, (v) => { if (v) fetchPackets() })
</script>

<style scoped>
.packet-summary { margin-bottom: 12px; display: flex; gap: 8px; }
.dir-out { color: #409eff; font-weight: 600; }
.dir-in { color: #67c23a; font-weight: 600; }
.hex-header { display: flex; justify-content: space-between; align-items: center; }
.hex-dump {
  background: #1e1e1e; color: #d4d4d4; padding: 12px;
  font-family: 'Cascadia Code', 'Fira Code', monospace;
  font-size: 12px; line-height: 1.6; overflow-x: auto;
  border-radius: 4px; margin: 0; max-height: 400px; overflow-y: auto;
}
</style>
