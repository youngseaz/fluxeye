/** Vue Router 路由配置 */

import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      name: 'dashboard',
      component: () => import('@/views/Dashboard.vue'),
      meta: { title: '实时仪表盘' },
    },
    {
      path: '/dns',
      name: 'dns-dashboard',
      component: () => import('@/views/DNSDashboard.vue'),
      meta: { title: 'DNS仪表盘' },
    },
    {
      path: '/live-sessions',
      name: 'live-sessions',
      component: () => import('@/views/LiveSessions.vue'),
      meta: { title: '实时会话' },
    },
    {
      path: '/history',
      name: 'history',
      component: () => import('@/views/History.vue'),
      meta: { title: '历史查询' },
    },
    {
      path: '/flows/:id',
      name: 'flow-detail',
      component: () => import('@/views/FlowDetail.vue'),
      meta: { title: '流详情' },
    },
    {
      path: '/settings',
      name: 'settings',
      component: () => import('@/views/Settings.vue'),
      meta: { title: '系统设置' },
    },
    {
      path: '/security',
      name: 'security',
      component: () => import('@/views/Security.vue'),
      meta: { title: '安全态势' },
    },
    {
      path: '/profiles',
      name: 'profiles',
      component: () => import('@/views/DeviceProfiles.vue'),
      meta: { title: '设备画像' },
    },
    {
      path: '/profiles/:ip',
      name: 'device-detail',
      component: () => import('@/views/DeviceDetail.vue'),
      meta: { title: '设备详情' },
    },
  ],
})

export default router
