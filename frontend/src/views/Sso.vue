<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<template>
  <div class="sso-wrap">
    <div class="sso-box">
      <div class="spinner" />
      <div class="sso-text">{{ text }}</div>
      <el-button v-if="failed" type="primary" link @click="toLogin">返回登录页</el-button>
    </div>
  </div>
</template>

<script setup>
/**
 * OIDC 回调落地页。
 *
 * 后端回调只种一个 2 分钟的 HttpOnly 交接票据就 302 到这里，访问令牌
 * 从不进 URL（避免出现在浏览器历史、Referer 与反向代理访问日志里）。
 * 本页唯一职责：POST /auth/oidc/session 换正式会话 → 进首页。
 */
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { auth } from '../api'
import { setSession } from '../session'

const router = useRouter()
const text = ref('正在完成企业单点登录…')
const failed = ref(false)

function toLogin() { router.push('#/login') }

onMounted(async () => {
  try {
    const res = await auth.ssoSession()
    // cookie 模式下令牌由服务端直接种进 HttpOnly Cookie，这里不存任何令牌
    setSession(res)
    router.push('/')
    location.reload()
  } catch (e) {
    failed.value = true
    text.value = e.response?.data?.detail || '单点登录未完成，请重新登录'
    ElMessage.error(text.value)
    setTimeout(() => router.push('/login'), 1500)
  }
})
</script>

<style scoped>
.sso-wrap { height: 100vh; display: grid; place-items: center; background: var(--bg); }
.sso-box { display: grid; place-items: center; gap: 12px; padding: 32px 40px;
  background: #fff; border: 1px solid var(--border); border-radius: 12px; }
.sso-text { color: #4a5568; font-size: 14px; }
.spinner { width: 26px; height: 26px; border-radius: 50%;
  border: 3px solid var(--brand-soft); border-top-color: var(--brand);
  animation: spin .8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
</style>
