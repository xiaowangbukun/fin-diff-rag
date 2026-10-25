<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<template>
  <div class="wrap">
    <div class="panel">
      <div class="left">
        <div class="lt">金融企业级 RAG 知识库</div>
        <div class="ls">密级 · ACL · 部门角色 三重管控，检索到生成的全链路防泄密</div>
        <ul class="feat">
          <li>前置 SQL 权限过滤 + 后置逐条校验，双闸防越权</li>
          <li>身份证 / 银行卡 / 手机号自动识别与按密级脱敏</li>
          <li>相关性未达阈值直接拒答，杜绝模型幻觉</li>
          <li>从上传到问答全链路审计留痕，可回溯</li>
        </ul>
      </div>
      <div class="right">
        <h3>{{ step === 1 ? '账号登录' : '动态口令' }}</h3>

        <!-- 第一步：账号 + 口令 -->
        <el-form v-if="step === 1" @submit.prevent="submit" size="large">
          <el-form-item><el-input v-model="form.username" placeholder="用户名" /></el-form-item>
          <el-form-item><el-input v-model="form.password" type="password" placeholder="密码" show-password /></el-form-item>
          <el-button type="primary" style="width:100%" :loading="loading" @click="submit">登 录</el-button>
        </el-form>

        <!-- 第二步：口令已过，等动态口令（TOTP）或一次性恢复码。挑战票据 5 分钟有效 -->
        <el-form v-else @submit.prevent="submitCode" size="large">
          <el-alert v-if="mfa.mode === 'totp'" type="info" :closable="false" show-icon
                    title="请输入手机验证器上的 6 位动态口令" style="margin-bottom:14px" />
          <el-alert v-else type="warning" :closable="false" show-icon
                    title="请输入一个未使用过的一次性恢复码（格式 XXXX-XXXX-XXXX）"
                    style="margin-bottom:14px" />
          <el-form-item v-if="mfa.mode === 'totp'">
            <el-input v-model="mfa.code" maxlength="6" placeholder="6 位数字"
                      class="code-input" @keyup.enter="submitCode" />
          </el-form-item>
          <el-form-item v-else>
            <el-input v-model="mfa.recoveryCode" maxlength="24" placeholder="XXXX-XXXX-XXXX"
                      class="recovery-input" @keyup.enter="submitCode" />
          </el-form-item>
          <el-button type="primary" style="width:100%" :loading="loading" @click="submitCode">验 证</el-button>
          <el-button link style="width:100%;margin-top:8px" @click="toggleMode">
            {{ mfa.mode === 'totp' ? '手机丢失？改用一次性恢复码' : '改用验证器动态口令' }}
          </el-button>
          <el-button link style="width:100%;margin-top:4px" @click="backToPassword">返回重新输入账号</el-button>
        </el-form>

        <!-- 企业单点登录：仅当服务端启用了 OIDC 才显示 -->
        <div v-if="providers.oidc.enabled" class="sso">
          <el-divider>或</el-divider>
          <el-button plain style="width:100%" @click="startSso">{{ providers.oidc.label }}</el-button>
        </div>

        <div class="tips">
          <div class="muted">演示账号</div>
          <div v-for="a in accounts" :key="a.u" class="acc" @click="fill(a)">
            <b>{{ a.d }}</b><span>{{ a.u }} / {{ a.p }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { auth } from '../api'
import { setSession } from '../session'

const router = useRouter()
const route = useRoute()
const form = reactive({ username: 'admin', password: 'Admin@123' })
const loading = ref(false)
const accounts = [
  { d: '管理员（绝密）', u: 'admin', p: 'Admin@123' },
  { d: '研究员（机密）', u: 'research01', p: 'User@123' },
  { d: '风控（机密）', u: 'risk01', p: 'User@123' },
  { d: '实习生（内部）', u: 'intern01', p: 'User@123' }
]

// 登录方式能力探测：口令永远可用；TOTP 第二步按账号是否已绑定触发；
// OIDC 按钮只在服务端启用时出现（避免"点了永远 404"）。
const providers = ref({ mfa: { enabled: true }, oidc: { enabled: false, label: '企业单点登录' } })
const step = ref(1)
// mode: totp = 验证器动态口令；recovery = 一次性恢复码（手机丢失/换机）
const mfa = reactive({ challenge: '', code: '', recoveryCode: '', mode: 'totp' })

// SSO 失败回跳的错误码 → 人话（错误码由后端定义，见 app/oidc.py OidcError）
const ssoErrors = {
  account_not_provisioned: '企业身份未开通本系统账号，请联系管理员建号',
  user_disabled: '账号已停用，请联系管理员',
  subject_conflict: '该账号已绑定其它企业身份，请联系管理员处理',
  state_mismatch: '登录请求已失效（可能被中断或跨浏览器），请重试',
  state_invalid: '登录请求已过期，请重试',
  id_token_invalid: '企业身份令牌校验失败，请联系管理员',
  token_exchange_failed: '企业身份校验失败，请稍后重试',
  idp_metadata_invalid: '企业身份配置异常，请联系管理员',
  idp_unavailable: '企业身份服务不可用，请稍后重试或用账号口令登录',
  idp_error: '企业身份服务返回错误，请重试',
  callback_invalid: '登录回调参数缺失，请重试'
}

const fill = (a) => { form.username = a.u; form.password = a.p }

onMounted(async () => {
  const code = route.query.sso_error
  if (code) ElMessage.error(ssoErrors[String(code)] || '单点登录失败，请重试')
  try { providers.value = await auth.providers() } catch (e) { /* 探测失败不影响口令登录 */ }
})

function afterLogin(res) {
  // Cookie 模式下 res.token 为空：会话只在 HttpOnly Cookie 里，localStorage
  // 不落任何令牌（见 session.js 的两种模式说明）。
  setSession(res)
  // 恢复码剩余告警要熬过整页刷新：存一次性 flash，由 App.vue 挂载时弹出
  if (res.recovery_warning) localStorage.setItem('finrag_flash', res.recovery_warning)
  router.push('/')
  location.reload()
}

async function submit() {
  loading.value = true
  try {
    const res = await auth.login(form.username, form.password)
    if (res.mfa_required) {
      // 口令已过但未拿到会话：只保留挑战票据，5 分钟内完成第二步
      mfa.challenge = res.challenge
      mfa.code = ''
      mfa.recoveryCode = ''
      mfa.mode = 'totp'
      step.value = 2
      ElMessage.info('口令验证通过，请输入动态口令')
      return
    }
    afterLogin(res)
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '登录失败')
  } finally {
    loading.value = false
  }
}

async function submitCode() {
  // 恢复码通道：与动态口令共用同一张挑战票据（口令已验过），不能绕过口令
  if (mfa.mode === 'recovery') {
    const raw = (mfa.recoveryCode || '').trim()
    if (raw.replace(/[^A-Za-z0-9]/g, '').length < 8) {
      ElMessage.error('请输入完整的恢复码（12 位字符）')
      return
    }
    loading.value = true
    try {
      afterLogin(await auth.loginMfa(mfa.challenge, '', raw))
    } catch (e) {
      ElMessage.error(e.response?.data?.detail || '恢复码验证失败')
    } finally {
      loading.value = false
    }
    return
  }
  if (!/^\d{4,8}$/.test(mfa.code)) {
    ElMessage.error('请输入验证器上的数字口令')
    return
  }
  loading.value = true
  try {
    const res = await auth.loginMfa(mfa.challenge, mfa.code)
    afterLogin(res)
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '动态口令验证失败')
  } finally {
    loading.value = false
  }
}

function toggleMode() {
  mfa.mode = mfa.mode === 'totp' ? 'recovery' : 'totp'
  mfa.code = ''
  mfa.recoveryCode = ''
}

function backToPassword() {
  step.value = 1
  mfa.challenge = ''
  mfa.code = ''
  mfa.recoveryCode = ''
  mfa.mode = 'totp'
}

function startSso() {
  // 整页跳转（不是 XHR）：IdP 授权页与回调都需要浏览器上下文与 HttpOnly cookie
  window.location.href = providers.value.oidc.start || '/api/auth/oidc/start'
}
</script>

<style scoped>
.wrap { height: 100vh; display: grid; place-items: center; background: linear-gradient(135deg, #16457e, #2b6cb0); }
.panel { display: flex; width: 860px; background: #fff; border-radius: 14px; overflow: hidden; box-shadow: 0 20px 50px rgba(0,0,0,.2); }
.left { flex: 1; background: var(--brand-soft); padding: 40px 32px; }
.lt { font-size: 21px; font-weight: 800; color: var(--brand); }
.ls { margin-top: 8px; font-size: 13px; color: #5b6b82; line-height: 1.7; }
.feat { margin-top: 22px; padding-left: 18px; color: #4a5568; font-size: 13px; line-height: 2; }
.right { width: 340px; padding: 40px 32px; }
h3 { margin: 0 0 22px; color: var(--brand); }
.tips { margin-top: 22px; border-top: 1px dashed #dfe6ee; padding-top: 12px; }
.acc { display: flex; justify-content: space-between; font-size: 12px; padding: 5px 0; cursor: pointer; color: #4a5568; }
.acc:hover { color: var(--brand); }
.acc span { color: #98a4b6; }
.sso { margin-top: 14px; }
.code-input :deep(input) { text-align: center; font-size: 22px; letter-spacing: 8px; }
.recovery-input :deep(input) { text-align: center; font-family: Consolas, monospace;
  font-size: 16px; letter-spacing: 2px; }
</style>
