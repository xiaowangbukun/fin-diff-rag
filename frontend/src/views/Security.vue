<!-- SPDX-License-Identifier: Apache-2.0 -->
<template>
  <div class="card">
    <div class="page-title">安全设置 · 动态口令（TOTP）</div>
    <div class="muted" style="margin-bottom:14px">
      动态口令是登录的第二因子：口令泄露后，攻击者仍需要你手机上的验证器才能登录。
      支持任意兼容 TOTP 的验证器（Google Authenticator / Microsoft Authenticator / 1Password 等）。
    </div>

    <el-alert v-if="me && me.mfa_setup_required" type="warning" :closable="false" show-icon
              title="管理员要求本账号必须绑定动态口令，绑定前无法使用其它功能。" />

    <el-descriptions :column="2" border style="margin-top:14px">
      <el-descriptions-item label="当前账号">{{ me?.username }}</el-descriptions-item>
      <el-descriptions-item label="绑定状态">
        <el-tag :type="me?.mfa_enabled ? 'success' : 'info'" size="small">
          {{ me?.mfa_enabled ? '已绑定' : '未绑定' }}
        </el-tag>
      </el-descriptions-item>
    </el-descriptions>

    <!-- 未绑定：口令再验 → 出密钥 → 输一次动态口令完成绑定 -->
    <div v-if="!me?.mfa_enabled" class="blk">
      <div class="step">第 1 步：验证当前口令</div>
      <el-input v-model="pw" type="password" show-password placeholder="当前登录口令"
                style="max-width:320px" />
      <el-button type="primary" style="margin-left:8px" :loading="busy" @click="startSetup">
        生成密钥
      </el-button>

      <div v-if="secret" class="step" style="margin-top:18px">第 2 步：录入验证器</div>
      <div v-if="secret" class="seed">
        <div class="muted">在验证器中"手动输入密钥"（类型：基于时间）：</div>
        <div class="code">{{ secret }}</div>
        <div class="muted">发行方 {{ issuer }} · {{ digits }} 位 · {{ period }} 秒刷新</div>
      </div>
      <div v-if="secret" class="row" style="margin-top:12px">
        <el-input v-model="code" maxlength="6" placeholder="验证器上的 6 位口令"
                  class="code-input" style="max-width:220px" />
        <el-button type="success" :loading="busy" @click="confirmSetup">完成绑定</el-button>
      </div>
    </div>

    <!-- 已绑定：可解绑（同样要口令再验，防"拿到会话就关 MFA"） -->
    <div v-else class="blk">
      <div class="step">解绑动态口令</div>
      <div class="muted">解绑后仅凭口令即可登录。若管理员要求强制绑定，解绑后将被立即拦回本页。</div>
      <div class="row" style="margin-top:10px">
        <el-input v-model="pw" type="password" show-password placeholder="当前登录口令"
                  style="max-width:320px" />
        <el-button type="danger" plain :loading="busy" @click="disable">解绑</el-button>
      </div>
    </div>

    <!-- 恢复码：手机丢失/换机时的一次性自助入口（每码只能用一次） -->
    <div v-if="me?.mfa_enabled" class="blk">
      <div class="step">一次性恢复码</div>
      <div class="muted">
        手机丢失/换机时，可用恢复码代替动态口令完成登录（仍需先验口令）。
        当前剩余
        <b :class="{ 'rc-low': (me?.recovery_codes_remaining || 0) <= 2 }">
          {{ me?.recovery_codes_remaining || 0 }}
        </b> 个。
      </div>
      <el-alert v-if="(me?.recovery_codes_remaining || 0) <= 2" type="warning"
                :closable="false" show-icon style="margin-top:10px"
                title="恢复码即将用尽：请重新生成并离线保存，否则只能联系管理员重置动态口令。" />
      <div class="row" style="margin-top:10px">
        <el-input v-model="rcPw" type="password" show-password placeholder="当前登录口令"
                  style="max-width:320px" />
        <el-button type="warning" plain :loading="busy" @click="regenerate">重新生成</el-button>
      </div>
      <div class="muted" style="margin-top:6px">重新生成后，旧的一整组恢复码立即作废。</div>
    </div>

    <RecoveryCodesDialog v-model="rcDialog" :codes="rcCodes" />
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { auth } from '../api'
import RecoveryCodesDialog from '../components/RecoveryCodesDialog.vue'

const me = ref(null)
const pw = ref('')
const code = ref('')
const secret = ref('')
const issuer = ref('FinRAG')
const digits = ref(6)
const period = ref(30)
const busy = ref(false)
// 恢复码：只在这一个弹窗里展示明文，关闭即从内存丢弃
const rcPw = ref('')
const rcCodes = ref([])
const rcDialog = ref(false)

async function load() {
  me.value = await auth.me()
  localStorage.setItem('finrag_user', JSON.stringify(me.value))
}

onMounted(load)

async function startSetup() {
  if (!pw.value) { ElMessage.error('请输入当前口令'); return }
  busy.value = true
  try {
    const res = await auth.totpSetup(pw.value)
    secret.value = res.secret
    issuer.value = res.issuer
    digits.value = res.digits
    period.value = res.period
    ElMessage.success('密钥已生成，请在验证器中录入后完成校验')
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '生成失败')
  } finally { busy.value = false }
}

async function confirmSetup() {
  busy.value = true
  try {
    const res = await auth.totpConfirm(code.value)
    // 绑定成功服务端会顺手发一组恢复码；明文只在这一刻返回，必须当场展示
    if (res.recovery_codes?.length) {
      rcCodes.value = res.recovery_codes
      rcDialog.value = true
    }
    ElMessage.success('动态口令已启用')
    secret.value = ''
    code.value = ''
    pw.value = ''
    await load()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '校验失败')
  } finally { busy.value = false }
}

async function regenerate() {
  if (!rcPw.value) { ElMessage.error('请输入当前口令'); return }
  busy.value = true
  try {
    const res = await auth.regenerateRecoveryCodes(rcPw.value)
    rcCodes.value = res.recovery_codes || []
    rcDialog.value = true
    rcPw.value = ''
    await load()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '生成失败')
  } finally { busy.value = false }
}

async function disable() {
  if (!pw.value) { ElMessage.error('请输入当前口令'); return }
  busy.value = true
  try {
    await auth.totpDisable(pw.value)
    ElMessage.success('已解绑动态口令')
    pw.value = ''
    await load()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '解绑失败')
  } finally { busy.value = false }
}
</script>

<style scoped>
.blk { margin-top: 20px; border-top: 1px dashed #dfe6ee; padding-top: 16px; }
.step { font-weight: 700; color: var(--brand); margin-bottom: 8px; }
.seed { background: var(--brand-soft); border-radius: 8px; padding: 12px 14px; max-width: 520px; }
.code { font-family: Consolas, monospace; font-size: 16px; letter-spacing: 2px;
  word-break: break-all; color: #16457e; margin: 6px 0; }
.row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.rc-low { color: #e6a23c; }
.code-input :deep(input) { text-align: center; letter-spacing: 6px; font-size: 18px; }
</style>
