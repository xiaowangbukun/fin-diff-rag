// SPDX-License-Identifier: Apache-2.0
import { createRouter, createWebHashHistory } from 'vue-router'
import Login from './views/Login.vue'
import Chat from './views/Chat.vue'
import Docs from './views/Docs.vue'
import Audit from './views/Audit.vue'
import Admin from './views/Admin.vue'
import Approvals from './views/Approvals.vue'
import Security from './views/Security.vue'
import Sso from './views/Sso.vue'

const routes = [
  { path: '/login', component: Login, meta: { public: true } },
  // SSO 回调落地页：只做"交接票据换会话"，public 是因为此时还没有本地令牌
  { path: '/sso', component: Sso, meta: { public: true } },
  { path: '/', component: Chat },
  { path: '/docs', component: Docs },
  { path: '/audit', component: Audit },
  { path: '/admin', component: Admin },
  { path: '/approvals', component: Approvals },
  { path: '/security', component: Security }
]

const router = createRouter({ history: createWebHashHistory(), routes })

router.beforeEach((to) => {
  if (!to.meta.public && !localStorage.getItem('finrag_token')) {
    return { path: '/login' }
  }
})

export default router
