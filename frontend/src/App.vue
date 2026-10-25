<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<template>
  <div v-if="!user" class="full"><router-view /></div>
  <el-container v-else class="layout">
    <el-header class="header">
      <div class="brand">
        <span class="logo">FR</span>
        <div>
          <div class="title">金融企业级 RAG 知识库</div>
          <div class="sub">全链路权限防泄密 · 检索增强问答</div>
        </div>
      </div>
      <div class="right">
        <el-tag type="info" size="small">{{ storage }}</el-tag>
        <el-tag :type="user.is_admin ? 'danger' : 'primary'" size="small">
          {{ user.display_name }} · 密级 {{ user.clearance_name }}
        </el-tag>
        <el-tag size="small" v-for="r in user.roles" :key="r">{{ roleLabel(r) }}</el-tag>
        <el-button link type="danger" @click="logout">退出</el-button>
      </div>
    </el-header>
    <el-container>
      <el-aside width="190px" class="aside">
        <el-menu :default-active="active" router>
          <el-menu-item index="/"><span>智能问答</span></el-menu-item>
          <el-menu-item index="/docs"><span>知识库管理</span></el-menu-item>
          <el-menu-item index="/audit"><span>审计日志</span></el-menu-item>
          <el-menu-item index="/security"><span>安全设置</span></el-menu-item>
          <el-menu-item v-if="user.is_admin" index="/approvals"><span>审批中心</span></el-menu-item>
          <el-menu-item v-if="user.is_admin" index="/admin"><span>用户与权限</span></el-menu-item>
        </el-menu>
      </el-aside>
      <el-main class="main">
        <router-view v-if="!mustChange && !mfaSetup" />
        <div v-else class="must-change-hold">
          {{ mustChange ? '请先完成初始口令修改' : '请先绑定动态口令' }}
        </div>
      </el-main>
    </el-container>

    <!-- 首次登录强制改密：服务端对其它接口一律 403，这里只负责给出口。
         不提供"稍后再说"——按钮只有"确认修改"和"退出登录"。 -->
    <el-dialog v-model="mustChange" title="首次登录须修改初始口令"
               width="440px" :close-on-click-modal="false" :show-close="false"
               :close-on-press-escape="false">
      <el-alert type="warning" :closable="false" show-icon
                title="初始口令由管理员设定，可能已被他人知晓；修改后方可使用系统。" />
      <el-form label-width="90px" style="margin-top:16px" @submit.prevent="submitChange">
        <el-form-item label="当前口令">
          <el-input v-model="pwd.old" type="password" show-password autocomplete="current-password" />
        </el-form-item>
        <el-form-item label="新口令">
          <el-input v-model="pwd.next" type="password" show-password autocomplete="new-password" />
          <div class="pwd-tip">≥12 位，大写/小写/数字/符号至少三类，不能包含用户名</div>
        </el-form-item>
        <el-form-item label="确认新口令">
          <el-input v-model="pwd.confirm" type="password" show-password autocomplete="new-password" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button type="danger" plain @click="logout">退出登录</el-button>
        <el-button type="primary" :loading="pwd.loading" @click="submitChange">确认修改</el-button>
      </template>
    </el-dialog>

    <!-- 强制绑定动态口令（MFA_ENFORCE_ADMIN / MFA_ENFORCE_ALL 开启时）：
         服务端同样有硬闸，这里只是给出绑定入口。同样不给"稍后再说"。 -->
    <el-dialog v-model="mfaSetup" title="须绑定动态口令（第二因子）"
               width="480px" :close-on-click-modal="false" :show-close="false"
               :close-on-press-escape="false">
      <el-alert type="warning" :closable="false" show-icon
                title="本账号被要求启用双因子认证：绑定后登录需口令 + 手机验证器动态口令。" />
      <el-form label-width="90px" style="margin-top:16px">
        <el-form-item label="当前口令">
          <el-input v-model="mfa.pwd" type="password" show-password />
          <el-button style="margin-top:8px" :loading="mfa.loading" @click="mfaGenerate">生成密钥</el-button>
        </el-form-item>
        <template v-if="mfa.secret">
          <el-form-item label="密钥">
            <div class="mfa-secret">{{ mfa.secret }}</div>
            <div class="pwd-tip">在手机验证器中手动录入该密钥（基于时间，6 位，30 秒）</div>
          </el-form-item>
          <el-form-item label="动态口令">
            <el-input v-model="mfa.code" maxlength="6" placeholder="验证器上的 6 位数字" />
          </el-form-item>
        </template>
      </el-form>
      <template #footer>
        <el-button type="danger" plain @click="logout">退出登录</el-button>
        <el-button type="primary" :disabled="!mfa.secret" :loading="mfa.loading"
                   @click="mfaConfirm">完成绑定</el-button>
      </template>
    </el-dialog>

    <!-- 绑定成功即发一组一次性恢复码：明文只返回这一次，必须当场让用户存好 -->
    <RecoveryCodesDialog v-model="rcDialog" :codes="rcCodes" />
  </el-container>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { auth } from './api'
import { cachedUser, clearSession, hasSession, setSession, setUser } from './session'
import RecoveryCodesDialog from './components/RecoveryCodesDialog.vue'

const route = useRoute()
const router = useRouter()
const user = ref(null)
const storage = ref('')
const mustChange = ref(false)
const pwd = reactive({ old: '', next: '', confirm: '', loading: false })
// 强制绑定动态口令（服务端 MFA_ENFORCE_* 判定，见 security.mfa_setup_required）
const mfaSetup = ref(false)
const mfa = reactive({ pwd: '', secret: '', code: '', loading: false })
// 绑定成功后的恢复码展示（明文只回这一次，见 RecoveryCodesDialog）
const rcCodes = ref([])
const rcDialog = ref(false)

const roleMap = { admin: '管理员', compliance: '合规', risk: '风控', research: '研究', trader: '交易', guest: '访客' }
const roleLabel = (r) => roleMap[r] || r
const active = computed(() => route.path)

onMounted(async () => {
  // 登录页写入的一次性提示（如"恢复码仅剩 N 个"）熬过整页刷新后在这里弹出
  const flash = localStorage.getItem('finrag_flash')
  if (flash) {
    localStorage.removeItem('finrag_flash')
    ElMessage.warning(flash)
  }
  const cached = cachedUser()
  // cookie 模式下 localStorage 没有令牌（HttpOnly Cookie 才是凭据），
  // 因此判据是"是否有可尝试的会话"，真假由 /auth/me 决定。
  if (!hasSession()) return
  try {
    const me = await auth.me()
    user.value = me
    mustChange.value = !!me.must_change_password
    mfaSetup.value = !!me.mfa_setup_required
    setUser(me)
  } catch (e) {
    if (cached) user.value = cached
  }
  try {
    const h = await (await fetch('/api/health')).json()
    // health.storage 恒为 postgresql+pgvector（唯一存储后端）；
    // 取不到值时按同一口径兜底展示。
    storage.value = h.storage || 'PG + pgvector'
  } catch (e) { storage.value = '' }
})

async function submitChange() {
  if (pwd.next !== pwd.confirm) {
    ElMessage.error('两次输入的新口令不一致')
    return
  }
  pwd.loading = true
  try {
    const res = await auth.changePassword(pwd.old, pwd.next)
    // 改密会吊销该账号的全部旧会话并重签本端会话：cookie 模式下新令牌走
    // Set-Cookie，bearer 模式下走 res.token——统一交给 setSession 处理。
    setSession(res)
    user.value = res.user
    mustChange.value = false
    pwd.old = pwd.next = pwd.confirm = ''
    ElMessage.success('口令已修改，旧会话已全部失效')
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '修改失败')
  } finally {
    pwd.loading = false
  }
}

async function mfaGenerate() {
  if (!mfa.pwd) { ElMessage.error('请输入当前口令'); return }
  mfa.loading = true
  try {
    const res = await auth.totpSetup(mfa.pwd)
    mfa.secret = res.secret
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '生成密钥失败')
  } finally { mfa.loading = false }
}

async function mfaConfirm() {
  mfa.loading = true
  try {
    const res = await auth.totpConfirm(mfa.code)
    mfaSetup.value = false
    mfa.pwd = mfa.secret = mfa.code = ''
    // 绑定即发放一次性恢复码：先让用户存好，再放开其它功能
    if (res.recovery_codes?.length) {
      rcCodes.value = res.recovery_codes
      rcDialog.value = true
    }
    const me = await auth.me()
    user.value = me
    setUser(me)
    ElMessage.success('动态口令已启用，后续登录需二次验证')
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '绑定失败')
  } finally { mfa.loading = false }
}

function logout() {
  // 服务端只吊销当前会话（其它设备不受影响，见“退出全部设备”）
  auth.logout().catch(() => {})
  clearSession()
  user.value = null
  router.push('/login')
}
</script>

<style>
:root {
  --brand: #16457e;
  --brand-soft: #eaf1fa;
  --bg: #f4f6f9;
  --border: #e2e8f0;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); font-family: "Microsoft YaHei", "PingFang SC", system-ui, sans-serif; color: #1f2937; }
.full { height: 100vh; }
.layout { height: 100vh; }
.header {
  display: flex; align-items: center; justify-content: space-between;
  background: #fff; border-bottom: 1px solid var(--border); padding: 0 20px;
}
.brand { display: flex; align-items: center; gap: 12px; }
.logo {
  width: 38px; height: 38px; border-radius: 8px; background: var(--brand);
  color: #fff; display: grid; place-items: center; font-weight: 700; letter-spacing: 1px;
}
.title { font-size: 15px; font-weight: 700; color: var(--brand); }
.sub { font-size: 12px; color: #8a94a6; }
.right { display: flex; align-items: center; gap: 8px; }
.aside { background: #fff; border-right: 1px solid var(--border); }
.aside .el-menu { border-right: none; }
.main { padding: 18px; overflow: auto; }
.must-change-hold { display: grid; place-items: center; height: 60vh; color: #8a94a6; }
.pwd-tip { font-size: 12px; color: #8a94a6; line-height: 1.6; margin-top: 4px; }
.mfa-secret { font-family: Consolas, monospace; font-size: 15px; letter-spacing: 2px;
  word-break: break-all; color: #16457e; background: var(--brand-soft);
  padding: 6px 10px; border-radius: 6px; }
.card { background: #fff; border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
.page-title { font-size: 16px; font-weight: 700; margin-bottom: 12px; color: var(--brand); }
.muted { color: #8a94a6; font-size: 12px; }
</style>
