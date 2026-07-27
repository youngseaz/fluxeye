<template>
  <div class="detail-page">
    <!-- 加载中 -->
    <el-skeleton :rows="8" animated v-if="loading" />

    <!-- 404 -->
    <el-empty description="未找到该流记录" v-else-if="!flow" />

    <!-- 详情 -->
    <template v-else>
      <el-page-header @back="goBack" content="流详情" style="margin-bottom: 16px" />

      <el-row :gutter="16">
        <!-- 基本信息 -->
        <el-col :span="12">
          <el-card shadow="hover">
            <template #header><span class="card-title">基本信息</span></template>
            <el-descriptions :column="2" border size="small">
              <el-descriptions-item label="流 ID">{{ flow.id }}</el-descriptions-item>
              <el-descriptions-item label="时间">{{ flow.timestamp }}</el-descriptions-item>
              <el-descriptions-item label="源 IP">{{ flow.src_ip }}</el-descriptions-item>
              <el-descriptions-item label="目标 IP">{{ flow.dst_ip }}</el-descriptions-item>
              <el-descriptions-item label="源端口">{{ flow.src_port }}</el-descriptions-item>
              <el-descriptions-item label="目标主机" v-if="flow.dst_host" :span="2">{{ flow.dst_host }}</el-descriptions-item>
              <el-descriptions-item label="抓包网卡" v-if="flow.interface" :span="2">{{ flow.interface }}</el-descriptions-item>
              <el-descriptions-item label="目标端口">{{ flow.dst_port }}</el-descriptions-item>
              <el-descriptions-item label="传输层">
                <el-tag size="small">{{ flow.l4_proto.toUpperCase() }}</el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="应用层">
                <el-tag :type="tagType" size="small">{{ flow.l7_proto.toUpperCase() }}</el-tag>
              </el-descriptions-item>
            </el-descriptions>
          </el-card>
        </el-col>

        <!-- 流量统计 -->
        <el-col :span="12">
          <el-card shadow="hover">
            <template #header><span class="card-title">流量统计</span></template>
            <el-descriptions :column="2" border size="small">
              <el-descriptions-item label="发送字节">{{ formatBytes(flow.bytes_sent) }}</el-descriptions-item>
              <el-descriptions-item label="接收字节">{{ formatBytes(flow.bytes_recv) }}</el-descriptions-item>
              <el-descriptions-item label="总流量">{{ formatBytes(flow.bytes_sent + flow.bytes_recv) }}</el-descriptions-item>
              <el-descriptions-item label="发送包数">{{ flow.packets_sent }}</el-descriptions-item>
              <el-descriptions-item label="接收包数">{{ flow.packets_recv }}</el-descriptions-item>
              <el-descriptions-item label="持续时间">{{ (flow.duration_ms / 1000).toFixed(2) }}s</el-descriptions-item>
            </el-descriptions>
          </el-card>
        </el-col>
      </el-row>

      <!-- 地理位置信息 -->
      <el-card shadow="hover" style="margin-top: 16px" v-if="flow.dst_asn || flow.dst_country">
        <template #header><span class="card-title">目标地理位置</span></template>
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item label="国家" v-if="flow.dst_country">
            <span :class="['fi', 'fi-' + flow.dst_country.toLowerCase(), 'geo-flag-icon']"></span>
            {{ countryName(flow.dst_country) }}
          </el-descriptions-item>
          <el-descriptions-item label="省/州" v-if="flow.dst_region">
            {{ flow.dst_region }}
          </el-descriptions-item>
          <el-descriptions-item label="城市" v-if="flow.dst_city">
            {{ flow.dst_city }}
          </el-descriptions-item>
          <el-descriptions-item label="ASN" v-if="flow.dst_asn">
            AS{{ flow.dst_asn }}
          </el-descriptions-item>
          <el-descriptions-item label="AS 组织" v-if="flow.dst_as_org">
            {{ flow.dst_as_org }}
          </el-descriptions-item>
          <el-descriptions-item label="经纬度" v-if="flow.dst_lat || flow.dst_lon">
            {{ flow.dst_lat?.toFixed(4) }}, {{ flow.dst_lon?.toFixed(4) }}
          </el-descriptions-item>
        </el-descriptions>
      </el-card>

      <!-- TLS 信息 -->
      <el-card shadow="hover" style="margin-top: 16px" v-if="isTLS">
        <template #header><span class="card-title">TLS 信息</span></template>
        <el-descriptions :column="1" border size="small">
          <el-descriptions-item label="协议">
            <el-tag type="success" size="small">TLS {{ flow.l7_proto.toUpperCase() }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="密钥可用">
            <el-tag :type="hasKey ? 'success' : 'warning'" size="small">
              {{ hasKey ? '✅ 有对应密钥（可用 Wireshark 解密）' : '❌ 无密钥' }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="目标端口" v-if="flow.dst_port === 443 || flow.dst_port === 8443">
            {{ flow.dst_port }} (HTTPS)
          </el-descriptions-item>
        </el-descriptions>
        <div style="font-size: 12px; color: #909399; margin-top: 8px">
          💡 设置 <code>SSLKEYLOGFILE</code> 环境变量启动浏览器/curl，
          FluxEye 自动捕获密钥并关联 TLS 流。
          导出的 pcap + keylog 可用 Wireshark 离线解密。
        </div>
      </el-card>

      <!-- 请求内容 -->
      <el-card shadow="hover" style="margin-top: 16px" v-if="flow.l7_meta">
        <template #header><span class="card-title">请求内容</span></template>
        <div class="request-content">{{ formatMeta(flow.l7_meta) }}</div>
      </el-card>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { fetchFlowDetail } from '@/services/api'
import type { Conversation } from '@/types'
import { countryName } from '@/utils/country'

const route = useRoute()
const router = useRouter()
const flow = ref<Conversation | null>(null)
const loading = ref(true)

const tagType = computed(() => {
  const m: Record<string, string> = { http: '', tls: 'success', dns: 'warning', quic: 'danger' }
  return m[flow.value?.l7_proto ?? ''] || 'info'
})

const isTLS = computed(() => {
  return flow.value?.l7_proto?.toLowerCase() === 'tls'
})

const hasKey = computed(() => {
  return flow.value?.l7_meta?.includes('tls_key_available=true') ?? false
})

function formatBytes(b: number) {
  if (b >= 1_000_000) return `${(b / 1_000_000).toFixed(2)} MB`
  if (b >= 1_000) return `${(b / 1_000).toFixed(2)} KB`
  return `${b} B`
}

function goBack() {
  router.back()
}

function formatMeta(meta: string): string {
  if (meta.startsWith('tls_key_available=true')) return '🔐 TLS 密钥可用'
  return meta
}

onMounted(async () => {
  const id = Number(route.params.id)
  if (id) {
    flow.value = await fetchFlowDetail(id)
  }
  loading.value = false
})
</script>

<style scoped>
.detail-page {
  max-width: 1400px;
  margin: 0 auto;
}
.card-title {
  font-weight: 600;
}
.meta-content {
  background: #f5f7fa;
  padding: 12px;
  border-radius: 4px;
  font-size: 13px;
  line-height: 1.6;
  overflow-x: auto;
}
</style>
