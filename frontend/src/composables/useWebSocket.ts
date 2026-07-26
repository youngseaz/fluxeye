/** WebSocket 组合式函数 — 实时数据推送 */

import { ref, onUnmounted } from 'vue'
import type { TrafficOverview } from '@/types'

export type WSDataCallback = (data: TrafficOverview) => void

export function useWebSocket(onData?: WSDataCallback) {
  const ws = ref<WebSocket | null>(null)
  const connected = ref(false)
  const lastData = ref<TrafficOverview | null>(null)
  const error = ref<string | null>(null)
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null
  let reconnectAttempts = 0
  const maxRetries = 5

  function connect() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.host
    const url = `${protocol}//${host}/api/v1/ws/live`

    try {
      ws.value = new WebSocket(url)
    } catch (e) {
      error.value = `WebSocket 连接失败: ${e}`
      return
    }

    ws.value.onopen = () => {
      connected.value = true
      error.value = null
      reconnectAttempts = 0
    }

    ws.value.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as TrafficOverview
        lastData.value = data
        if (onData) onData(data)
      } catch {
        // ignore malformed messages
      }
    }

    ws.value.onclose = () => {
      connected.value = false
      if (reconnectAttempts < maxRetries) {
        reconnectTimer = setTimeout(() => {
          reconnectAttempts++
          connect()
        }, 3000)
      }
    }

    ws.value.onerror = () => {
      error.value = 'WebSocket 连接错误'
    }
  }

  function disconnect() {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
    if (ws.value) {
      ws.value.close()
      ws.value = null
    }
    connected.value = false
  }

  onUnmounted(() => {
    disconnect()
  })

  return {
    connected,
    lastData,
    error,
    connect,
    disconnect,
  }
}
