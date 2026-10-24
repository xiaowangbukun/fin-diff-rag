<!-- SPDX-License-Identifier: Apache-2.0 -->
<template>
  <div class="grid">
    <div class="card chat">
      <div class="page-title">智能问答（仅依据您授权范围内的资料作答）</div>
      <div class="msgs" ref="box">
        <div v-if="!list.length" class="empty">
          <p class="muted">您可以试着问：</p>
          <el-button v-for="q in samples" :key="q" size="small" round @click="ask(q)">{{ q }}</el-button>
        </div>
        <div v-for="(m, i) in list" :key="i" class="msg">
          <div class="q"><span class="who">我</span>{{ m.q }}</div>
          <div class="a">
            <span class="who sys">助手</span>
            <div class="body">
              <el-alert v-if="m.blocked" type="warning" :closable="false" show-icon :title="m.block_reason || '已按防泄密策略拦截'" class="mb" />
              <el-alert v-if="m.probe_total || (m.denied_docs && m.denied_docs.length)" type="info" :closable="false" show-icon class="mb"
                :title="`已拦截越权文档 ${m.denied_docs?.length || 0} 篇；本次检索另有 ${m.probe_total || 0} 段越权候选被权限闸门挡下`">
                <template v-if="m.denied_docs?.length" #default>
                  <div v-for="(d, k) in m.denied_docs" :key="k" class="denyrow">
                    <template v-if="d.doc_ref">
                      <code>#{{ d.doc_ref }}</code>
                      <el-tag size="small" type="danger">{{ d.clearance }}</el-tag>
                      <span>{{ d.reason }}</span>
                    </template>
                    <span v-else class="muted">越权文档（编号/密级/原因仅对管理员可见）</span>
                  </div>
                </template>
              </el-alert>
              <el-alert v-if="m.intent && m.intent.level === 'danger'" type="error" :closable="false" show-icon class="mb"
                :title="`意图识别网关：${(m.intent.signals || []).join('；') || '拼图式诱导探针'}`" />
              <el-alert v-if="m.intent && m.intent.level === 'risky'" type="warning" :closable="false" show-icon class="mb"
                :title="`推理距离约束已启用：${(m.intent.signals || []).join('；') || '跨域组合联想'}——仅基于单一文档作答，不做跨文档归纳推断`" />
              <el-alert v-if="m.fail_secure" type="error" :closable="false" show-icon class="mb"
                title="Fail-Secure 安全降级：权限/检索组件异常，内部知识库已切断，本次仅基于 Public 公开域作答" />
              <el-alert v-if="m.jigsaw && m.jigsaw.level && m.jigsaw.level !== 'none'"
                :type="jigType(m.jigsaw.level)" :closable="false" show-icon class="mb"
                :title="jigTitle(m.jigsaw)">
                <template v-if="m.jigsaw.docs && m.jigsaw.docs.length" #default>
                  <div v-for="d in m.jigsaw.docs" :key="d.doc_id" class="jigrow">
                    <span class="jtitle">{{ d.title }}</span>
                    <span class="jcov">已披露 {{ d.seen }}/{{ d.total }} 段（{{ Math.round(d.coverage * 100) }}%）</span>
                    <el-tag size="small" :type="d.capped ? 'danger' : 'info'">
                      {{ d.capped ? '已限流' : (d.delivered ? `新披露 ${d.delivered} 段` : '重放已见内容') }}
                    </el-tag>
                  </div>
                </template>
              </el-alert>
              <el-tag v-if="m.masked" size="small" type="warning" class="mb">输出含敏感标识，已按您的密级脱敏</el-tag>
              <el-alert v-if="m.inject_flag" type="warning" :closable="false" show-icon class="mb"
                title="检测到疑似提示注入内容：本轮回答已标记并留痕，请谨慎采信（后端可开启 INJECT_BLOCK_OUTPUT 直接拦截）" />
              <el-tag v-if="m.degraded" size="small" type="info" class="mb">受限模式：未配置大模型，展示原文抽取结果</el-tag>
              <div class="text" v-html="fmt(m.answer)"></div>
              <div v-if="m.citations && m.citations.length" class="cites">
                <div class="ct">引用溯源（{{ m.citations.length }}）</div>
                <el-collapse>
                  <el-collapse-item v-for="(c, k) in m.citations" :key="k">
                    <template #title>
                      <span class="idx">[{{ k + 1 }}]</span>
                      <span class="ctitle">{{ c.doc_title }}</span>
                      <el-tag size="small" :type="levelType(c.clearance)">{{ c.clearance_name }}</el-tag>
                      <span class="score">相关度 {{ c.score }}</span>
                    </template>
                    <div class="snippet">{{ c.snippet }}</div>
                  </el-collapse-item>
                </el-collapse>
              </div>
            </div>
          </div>
        </div>
        <div v-if="loading" class="muted">检索中…（正在按您的权限过滤并校验）</div>
      </div>
      <div class="input">
        <el-input v-model="q" type="textarea" :rows="2" placeholder="输入问题，例如：信用债黑名单的准入标准是什么？"
          @keydown.ctrl.enter="ask()" />
        <div class="ops">
          <span class="muted">Ctrl + Enter 发送 · 当前密级 {{ me?.clearance_name }}</span>
          <el-button type="primary" :loading="loading" @click="ask()">提问</el-button>
        </div>
      </div>
    </div>
    <div class="card side">
      <div class="page-title">可见范围</div>
      <div class="kv"><span>账号</span><b>{{ me?.username }}</b></div>
      <div class="kv"><span>部门</span><b>{{ me?.dept_name }}</b></div>
      <div class="kv"><span>角色</span><b>{{ (me?.roles || []).join('、') || '-' }}</b></div>
      <div class="kv"><span>密级</span><b>{{ me?.clearance_name }}</b></div>
      <el-divider />
      <div class="page-title">存储与模型</div>
      <div class="kv"><span>存储</span><b>{{ stats.storage }}</b></div>
      <div class="kv"><span>向量</span><b>{{ stats.embed_mode }}</b></div>
      <div class="kv"><span>生成</span><b>{{ stats.llm_mode }}</b></div>
      <el-divider />
      <div class="page-title">近 7 日拦截</div>
      <div class="deny">{{ stats.denied_7d }} 次</div>
      <div class="muted">包含越权拒绝与相关性拒答</div>
      <el-divider />
      <div class="page-title">防拼图</div>
      <div class="kv"><span>近7日限流</span><b>{{ stats.throttled_7d ?? '-' }} 次</b></div>
      <div class="kv"><span>高风险组合</span><b>{{ stats.jigsaw_risk ?? '-' }}</b></div>
      <div class="muted">按累积披露量裁决，防止多轮提问把一篇文档逐步拼出全貌</div>
    </div>
  </div>
</template>

<script setup>
import { nextTick, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { admin, auth, chat as chatApi } from '../api'

const q = ref('')
const list = ref([])
const loading = ref(false)
const me = ref(null)
const stats = ref({})
const box = ref(null)
const samples = ['信用债黑名单的准入标准是什么？', '稳健增利理财产品的风险等级和费率？', '可疑交易报告要在几个工作日内提交？', '并购预案的估值区间是多少？']

const levelType = (c) => ({ 0: 'success', 1: 'info', 2: 'warning', 3: 'danger' }[c] || 'info')
const jigType = (lv) => ({ warn: 'warning', restrict: 'error', block: 'error' }[lv] || 'info')
const jigTitle = (j) => j.level === 'block' ? '已触发防拼图保护，本轮暂停应答'
  : j.level === 'restrict' ? '防拼图保护：已停止供给相关文档的新内容'
  : '防拼图提示：相关文档累计披露比例偏高，已限流'

function fmt(t) {
  const esc = (t || '').replace(/[&<>]/g, (s) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[s]))
  return esc.replace(/\[(\d+)\]/g, '<sup class="ref">[$1]</sup>').replace(/\n/g, '<br/>')
}

async function ask(text) {
  const query = (text || q.value || '').trim()
  if (!query) return
  q.value = ''
  loading.value = true
  try {
    const r = await chatApi.ask(query)
    list.value.push({
      q: query, answer: r.answer, citations: r.citations, blocked: r.blocked,
      block_reason: r.block_reason, denied_docs: r.denied_docs, masked: r.masked,
      degraded: r.degraded, probe_total: r.probe_total || 0, jigsaw: r.jigsaw || {},
      intent: r.intent || {}, fail_secure: !!r.fail_secure, verify: r.verify || {},
      inject_flag: !!r.inject_flag,
    })
    await nextTick()
    box.value?.scrollTo({ top: box.value.scrollHeight, behavior: 'smooth' })
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '请求失败')
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  try { me.value = await auth.me() } catch (e) {}
  try { stats.value = await admin.stats() } catch (e) {}
})
</script>

<style scoped>
.grid { display: grid; grid-template-columns: 1fr 280px; gap: 16px; height: calc(100vh - 96px); }
.chat { display: flex; flex-direction: column; }
.msgs { flex: 1; overflow: auto; padding: 4px 6px; }
.empty { padding: 40px 8px; text-align: center; }
.empty .el-button { margin: 6px 5px 0 0; }
.msg { margin-bottom: 20px; }
.q, .a { display: flex; gap: 10px; }
.q { justify-content: flex-end; text-align: right; margin-bottom: 10px; }
.who { flex: none; font-size: 12px; color: #98a4b6; padding-top: 2px; }
.sys { color: var(--brand); font-weight: 700; }
.body { flex: 1; background: #f8fafc; border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; }
.text { line-height: 1.85; font-size: 14px; white-space: normal; }
:deep(.ref) { color: var(--brand); font-weight: 700; }
.mb { margin-bottom: 10px; }
.cites { margin-top: 12px; border-top: 1px dashed #dfe6ee; padding-top: 10px; }
.ct { font-size: 12px; color: #6b7280; margin-bottom: 6px; }
.idx { color: var(--brand); font-weight: 700; margin-right: 6px; }
.ctitle { margin-right: 8px; font-size: 13px; }
.score { float: right; color: #98a4b6; font-size: 12px; }
.snippet { background: #fff; border: 1px solid var(--border); border-radius: 6px; padding: 10px; font-size: 13px; line-height: 1.8; white-space: pre-wrap; }
.input { margin-top: 14px; }
.ops { display: flex; justify-content: space-between; align-items: center; margin-top: 10px; }
.kv { display: flex; justify-content: space-between; font-size: 13px; padding: 6px 0; color: #4a5568; }
.kv span { color: #8a94a6; }
.deny { font-size: 26px; font-weight: 800; color: #c0392b; }
.denyrow { display: flex; align-items: center; gap: 8px; font-size: 12px; padding: 2px 0; }
.denyrow code { color: #98a4b6; }
.jigrow { display: flex; align-items: center; gap: 8px; font-size: 12px; padding: 2px 0; }
.jigrow .jtitle { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.jigrow .jcov { color: #8a94a6; flex: none; }
</style>
