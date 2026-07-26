<template>
  <div class="history-page">
    <!-- 筛选条件 -->
    <el-card shadow="hover" style="margin-bottom: 16px">
      <el-form :inline="true" :model="filters" size="small">
        <el-form-item label="协议">
          <el-select v-model="filters.l7_proto" placeholder="全部" clearable style="width: 120px">
            <el-option label="HTTP" value="http" />
            <el-option label="TLS" value="tls" />
            <el-option label="DNS" value="dns" />
            <el-option label="QUIC" value="quic" />
            <el-option label="SSH" value="ssh" />
            <el-option label="SMTP" value="smtp" />
          </el-select>
        </el-form-item>
        <el-form-item label="源 IP">
          <el-input v-model="filters.src_ip" placeholder="192.168.1.1" style="width: 150px" />
        </el-form-item>
        <el-form-item label="目标 IP">
          <el-input v-model="filters.dst_ip" placeholder="10.0.0.1" style="width: 150px" />
        </el-form-item>
        <el-form-item label="时间">
          <el-date-picker
            v-model="timeRange"
            type="datetimerange"
            range-separator="至"
            start-placeholder="开始"
            end-placeholder="结束"
            format="YYYY-MM-DD HH:mm"
            style="width: 320px"
          />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :icon="Search" @click="search">查询</el-button>
          <el-button :icon="Refresh" @click="reset">重置</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- 结果表格 -->
    <el-card shadow="hover">
      <el-table :data="tableData" stripe size="small" style="width: 100%" @row-click="goDetail">
        <el-table-column prop="timestamp" label="时间" width="170">
          <template #default="{ row }">{{ formatTime(row.timestamp) }}</template>
        </el-table-column>
        <el-table-column label="源" width="155">
          <template #default="{ row }">
            {{ row.src_ip }}:{{ row.src_port }}
          </template>
        </el-table-column>
        <el-table-column label="目标" width="155">
          <template #default="{ row }">
            {{ row.dst_ip }}:{{ row.dst_port }}
          </template>
        </el-table-column>
        <el-table-column label="主机" width="160">
          <template #default="{ row }">
            <span v-if="row.dst_host">{{ row.dst_host }}</span>
            <span v-else style="color:#c0c4cc">-</span>
          </template>
        </el-table-column>
        <el-table-column label="网卡" width="80">
          <template #default="{ row }">
            <span v-if="row.interface">{{ row.interface }}</span>
            <span v-else style="color:#c0c4cc">-</span>
          </template>
        </el-table-column>
        <el-table-column label="目标位置" width="160">
          <template #default="{ row }">
            <span v-if="row.dst_country">
              <span :class="['fi', 'fi-' + row.dst_country.toLowerCase(), 'geo-flag-icon']"></span>
              {{ row.dst_country }}<span v-if="row.dst_region"> / {{ row.dst_region }}</span>
              <span v-if="row.dst_city"> / {{ row.dst_city }}</span>
              <span v-if="row.dst_asn" style="color:#909399;font-size:11px"> AS{{ row.dst_asn }}</span>
            </span>
            <span v-else style="color:#c0c4cc">-</span>
          </template>
        </el-table-column>
        <el-table-column prop="l4_proto" label="传输" width="70">
          <template #default="{ row }">
            <el-tag size="small">{{ row.l4_proto?.toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="bytes_sent" label="发送" width="90">
          <template #default="{ row }">{{ formatBytes(row.bytes_sent) }}</template>
        </el-table-column>
        <el-table-column prop="bytes_recv" label="接收" width="90">
          <template #default="{ row }">{{ formatBytes(row.bytes_recv) }}</template>
        </el-table-column>
        <el-table-column prop="duration_ms" label="时长" width="80">
          <template #default="{ row }">{{ (row.duration_ms / 1000).toFixed(1) }}s</template>
        </el-table-column>
        <el-table-column label="操作" width="80">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click.stop="goDetail(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>

      <!-- 分页 -->
      <div class="pagination">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :total="total"
          :page-sizes="[15, 30, 50]"
          layout="total, sizes, prev, pager, next"
          @change="search"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { Search, Refresh } from '@element-plus/icons-vue'
import { fetchConversations } from '@/services/api'
import type { Conversation } from '@/types'

const router = useRouter()

const filters = ref({ l7_proto: '', src_ip: '', dst_ip: '' })
const timeRange = ref<[Date, Date] | null>(null)
const currentPage = ref(1)
const pageSize = ref(15)
const total = ref(0)
const tableData = ref<Conversation[]>([])

function formatTime(ts: string) {
  return new Date(ts).toLocaleString('zh-CN')
}
function formatBytes(b: number) {
  if (b >= 1_000_000) return `${(b / 1_000_000).toFixed(1)}MB`
  if (b >= 1_000) return `${(b / 1_000).toFixed(1)}KB`
  return `${b}B`
}
function tagType(p: string) {
  const m: Record<string, string> = { http: '', tls: 'success', dns: 'warning', quic: 'danger' }
  return m[p] || 'info'
}
function goDetail(row: any) { router.push(`/flows/${row.id}`) }

async function search() {
  const params: any = {
    page: currentPage.value,
    size: pageSize.value,
  }
  if (filters.value.l7_proto) params.l7_proto = filters.value.l7_proto
  if (filters.value.src_ip) params.src_ip = filters.value.src_ip
  if (filters.value.dst_ip) params.dst_ip = filters.value.dst_ip
  if (timeRange.value?.[0]) params.time_start = timeRange.value[0].toISOString()
  if (timeRange.value?.[1]) params.time_end = timeRange.value[1].toISOString()

  const res = await fetchConversations(params)
  tableData.value = res.items
  total.value = res.total
  currentPage.value = res.page
}

function reset() {
  filters.value = { l7_proto: '', src_ip: '', dst_ip: '' }
  timeRange.value = null
  currentPage.value = 1
  search()
}

search()
</script>

<style>
.geo-flag-icon {
  display: inline-block;
  vertical-align: middle;
  margin-right: 4px;
  line-height: 1;
}
</style>
<style scoped>
.history-page {
  max-width: 1400px;
  margin: 0 auto;
}
.pagination {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
}
</style>
