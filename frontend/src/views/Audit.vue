<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<template>
  <div>
    <div class="bar">
      <div class="page-title">审计日志（全链路留痕）</div>
      <div class="filters">
        <el-select v-model="f.action" clearable placeholder="动作" style="width:130px" @change="load">
          <el-option v-for="a in actions" :key="a.v" :label="a.l" :value="a.v" />
        </el-select>
        <el-select v-model="f.decision" clearable placeholder="判定" style="width:120px" @change="load">
          <el-option label="允许" value="allow" /><el-option label="拒绝" value="deny" />
          <el-option label="拒答" value="abstain" /><el-option label="脱敏" value="mask" />
          <el-option label="防拼图限流" value="throttle" />
          <el-option label="意图阻断" value="block" />
          <el-option label="推理约束" value="constrain" />
          <el-option label="安全降级" value="degrade" />
        </el-select>
        <el-input v-model="f.username" placeholder="账号" style="width:140px" clearable @change="load" />
        <el-button @click="load">刷新</el-button>
      </div>
    </div>
    <el-table :data="rows" border stripe @row-click="detail">
      <el-table-column prop="ts" label="时间" width="160" />
      <el-table-column prop="username" label="账号" width="120" />
      <el-table-column label="动作" width="110">
        <template #default="{ row }">{{ actionLabel(row.action) }}</template>
      </el-table-column>
      <el-table-column prop="target_label" label="对象" min-width="180" />
      <el-table-column prop="query" label="提问 / 内容" min-width="200" show-overflow-tooltip />
      <el-table-column label="判定" width="90">
        <template #default="{ row }">
          <el-tag size="small" :type="decType(row.decision)">{{ decLabel(row.decision) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="reason" label="原因" min-width="220" show-overflow-tooltip />
      <el-table-column label="链哈希" width="96">
        <template #default="{ row }">
          <span v-if="row.row_hash" style="font-family:monospace;font-size:12px"
                :title="`row_hash ${row.row_hash}`">{{ row.row_hash.slice(0, 8) }}</span>
          <span v-else class="muted" title="迁移前历史行，不在链上">—</span>
        </template>
      </el-table-column>
    </el-table>
    <div class="muted" style="margin-top:8px">点击任意行查看完整详情（含命中切片、被拦截文档、越权候选统计）</div>

    <el-drawer v-model="d.open" title="审计详情" size="50%">
      <pre class="json">{{ d.json }}</pre>
    </el-drawer>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { admin } from '../api'

const rows = ref([])
const f = reactive({ action: '', decision: '', username: '' })
const d = reactive({ open: false, json: '' })
const actions = [
  { v: 'login', l: '登录' }, { v: 'chat', l: '问答' }, { v: 'upload', l: '录入' },
  { v: 'view', l: '查看' }, { v: 'grant', l: '授权' }, { v: 'revoke', l: '撤销授权' },
  { v: 'update', l: '修改' }, { v: 'delete', l: '删除' },
  { v: 'create_user', l: '创建用户' }, { v: 'update_user', l: '修改用户' }
]
const actionLabel = (a) => (actions.find((x) => x.v === a) || { l: a }).l
const decLabel = (v) => ({ allow: '允许', deny: '拒绝', abstain: '拒答', mask: '脱敏', throttle: '防拼图限流' }[v] || v)
const decType = (v) => ({ allow: 'success', deny: 'danger', abstain: 'warning', mask: 'warning', throttle: 'danger' }[v] || 'info')

async function load() {
  rows.value = await admin.audit({ action: f.action || undefined, decision: f.decision || undefined, username: f.username || undefined, limit: 200 })
}

async function detail(row) {
  const r = await admin.auditDetail(row.id)
  d.json = JSON.stringify(r, null, 2)
  d.open = true
}

onMounted(load)
</script>

<style scoped>
.bar { display: flex; justify-content: space-between; align-items: center; }
.filters { display: flex; gap: 8px; }
.json { background: #f8fafc; border: 1px solid var(--border); border-radius: 8px; padding: 12px; font-size: 12px; overflow: auto; }
</style>
