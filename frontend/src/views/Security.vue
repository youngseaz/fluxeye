<template>
  <div class="security-page">
    <!-- 概览卡片 -->
    <el-row :gutter="16" style="margin-bottom: 16px">
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card risk-critical">
          <div class="stat-inner">
            <div class="stat-icon">🔴</div>
            <div class="stat-body">
              <div class="stat-value">{{ overview.critical_count }}</div>
              <div class="stat-label">严重风险</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card risk-high">
          <div class="stat-inner">
            <div class="stat-icon">🟠</div>
            <div class="stat-body">
              <div class="stat-value">{{ overview.high_count }}</div>
              <div class="stat-label">高危风险</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card risk-medium">
          <div class="stat-inner">
            <div class="stat-icon">🟡</div>
            <div class="stat-body">
              <div class="stat-value">{{ overview.medium_count }}</div>
              <div class="stat-label">中危风险</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card risk-low">
          <div class="stat-inner">
            <div class="stat-icon">🟢</div>
            <div class="stat-body">
              <div class="stat-value">{{ overview.low_count }}</div>
              <div class="stat-label">低危风险</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 时间范围选择 + 总事件数 -->
    <el-row :gutter="16" style="margin-bottom: 16px" align="middle">
      <el-col :span="12">
        <div class="section-title">
          安全事件
          <el-tag size="small" type="warning" style="margin-left: 8px">
            共 {{ overview.total_events }} 条
          </el-tag>
        </div>
      </el-col>
      <el-col :span="12" style="text-align: right">
        <el-radio-group v-model="timeRange" size="small" @change="fetchData">
          <el-radio-button value="5m">5分钟</el-radio-button>
          <el-radio-button value="15m">15分钟</el-radio-button>
          <el-radio-button value="1h">1小时</el-radio-button>
          <el-radio-button value="6h">6小时</el-radio-button>
          <el-radio-button value="24h">24小时</el-radio-button>
        </el-radio-group>
      </el-col>
    </el-row>

    <!-- 加载态 -->
    <el-skeleton :rows="5" animated v-if="loading" />

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

    <!-- 空状态 -->
    <el-empty v-if="!loading && !error && events.length === 0" description="暂未检测到安全事件" />

    <!-- 安全事件列表 -->
    <el-timeline v-if="events.length > 0">
      <el-timeline-item
        v-for="evt in events"
        :key="evt.timestamp + evt.src_ip + evt.dst_ip"
        :timestamp="formatTime(evt.timestamp)"
        :color="severityColor(evt.risk_level)"
      >
        <el-card shadow="hover" class="event-card" :class="'event-' + evt.risk_level">
          <div class="event-header">
            <div class="event-summary">
              <el-tag :type="severityTagType(evt.risk_level)" size="small" effect="dark">
                {{ evt.risk_level.toUpperCase() }}
              </el-tag>
              <el-tag size="small" style="margin-left: 6px">
                ️{{ evt.l7_proto }}
              </el-tag>
              <span class="event-ip" style="margin-left: 8px">
                {{ evt.src_ip }}:{{ evt.src_port }}
                <el-icon><ArrowRight /></el-icon>
                {{ evt.dst_ip }}:{{ evt.dst_port }}
              </span>
              <el-tag size="small" type="info" style="margin-left: 6px">
                风险分 {{ evt.risk_score }}
              </el-tag>
            </div>
            <div class="event-meta">
              <span v-if="evt.dst_host" class="meta-item">{{ evt.dst_host }}</span>
              <span v-if="evt.dst_country" class="meta-item">{{ evt.dst_country }}</span>
              <span v-if="evt.interface" class="meta-item">{{ evt.interface }}</span>
            </div>
          </div>
          <div class="event-risks">
            <el-tag
              v-for="risk in evt.risks"
              :key="risk.id"
              size="small"
              :type="riskSeverityType(risk.severity)"
              style="margin: 2px 4px 2px 0"
            >
              {{ risk.name }}
            </el-tag>
          </div>
        </el-card>
      </el-timeline-item>
    </el-timeline>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ArrowRight } from '@element-plus/icons-vue'
import { fetchSecurityOverview, fetchSecurityEvents } from '@/services/api'
import type { SecurityEvent, SecurityOverview } from '@/types'

const loading = ref(false)
const error = ref('')
const timeRange = ref('1h')

const overview = reactive<SecurityOverview>({
  total_events: 0,
  critical_count: 0,
  high_count: 0,
  medium_count: 0,
  low_count: 0,
  top_risks: [],
  by_severity: [],
  time_range: '1h',
})

const events = ref<SecurityEvent[]>([])

async function fetchData() {
  loading.value = true
  error.value = ''
  try {
    const [ov, evts] = await Promise.all([
      fetchSecurityOverview(timeRange.value),
      fetchSecurityEvents(timeRange.value),
    ])
    Object.assign(overview, ov)
    events.value = evts
  } catch (e: any) {
    error.value = '获取安全态势数据失败: ' + (e?.message || '未知错误')
  } finally {
    loading.value = false
  }
}

function formatTime(isoStr: string): string {
  const d = new Date(isoStr)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

function severityColor(level: string): string {
  const map: Record<string, string> = {
    emergency: '#e61919',
    critical: '#e61919',
    severe: '#ff6b35',
    high: '#ff8c00',
    medium: '#f5c518',
    low: '#52c41a',
  }
  return map[level] || '#909399'
}

function severityTagType(level: string): string {
  const map: Record<string, string> = {
    critical: 'danger',
    severe: 'danger',
    high: 'warning',
    medium: 'warning',
    low: 'info',
  }
  return map[level] || 'info'
}

function riskSeverityType(severity: number): string {
  if (severity >= 4) return 'danger'
  if (severity >= 2) return 'warning'
  return 'info'
}

onMounted(fetchData)
</script>

<style scoped>
.security-page {
  max-width: 1400px;
  margin: 0 auto;
}

.section-title {
  font-size: 16px;
  font-weight: 600;
  display: flex;
  align-items: center;
}

/* 统计卡片 */
.stat-card {
  border-left: 4px solid;
}
.stat-card.risk-critical { border-left-color: #e61919; }
.stat-card.risk-high { border-left-color: #ff8c00; }
.stat-card.risk-medium { border-left-color: #f5c518; }
.stat-card.risk-low { border-left-color: #52c41a; }

.stat-inner {
  display: flex;
  align-items: center;
  gap: 12px;
}
.stat-icon {
  font-size: 28px;
  line-height: 1;
}
.stat-body {
  flex: 1;
}
.stat-value {
  font-size: 28px;
  font-weight: 700;
  line-height: 1.2;
}
.stat-label {
  font-size: 13px;
  color: #909399;
}

/* 事件卡片 */
.event-card {
  transition: box-shadow 0.2s;
}
.event-card:hover {
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.12);
}
.event-card.event-critical { border-left: 3px solid #e61919; }
.event-card.event-severe { border-left: 3px solid #ff6b35; }
.event-card.event-high { border-left: 3px solid #ff8c00; }
.event-card.event-medium { border-left: 3px solid #f5c518; }
.event-card.event-low { border-left: 3px solid #52c41a; }

.event-header {
  margin-bottom: 8px;
}
.event-summary {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 4px;
}
.event-ip {
  font-family: 'SF Mono', 'Cascadia Code', monospace;
  font-size: 13px;
  color: #303133;
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.event-meta {
  margin-top: 4px;
  font-size: 12px;
  color: #909399;
}
.meta-item + .meta-item::before {
  content: ' · ';
}
.event-risks {
  display: flex;
  flex-wrap: wrap;
  gap: 2px;
}
</style>
