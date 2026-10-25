// SPDX-License-Identifier: Apache-2.0
import { createRouter, createWebHashHistory } from 'vue-router'
import { hasSession } from './session'
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
  // cookie 模式下没有可读令牌，只有模式标志位；两者之一存在即视为"可能已登录"，
  // 真实性一律由服务端 /auth/me 判定（401 时 api.js 会清会话并回登录页）。
  if (!to.meta.public && !hasSession()) {
    return { path: '/login' }
  }
})

export default router
