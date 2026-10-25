<!-- SPDX-License-Identifier: Apache-2.0 -->
<template>
  <div>
    <div class="bar">
      <div class="page-title">审批中心（权限变更双人复核）</div>
      <div class="filters">
        <el-radio-group v-model="tab" size="small">
          <el-radio-button value="pending">待审批（{{ pending.length }}）</el-radio-button>
          <el-radio-button value="decided">已处理（{{ decided.length }}）</el-radio-button>
        </el-radio-group>
        <el-button :loading="loading" @click="load">刷新</el-button>
      </div>
    </div>

    <el-alert class="tip" type="info" :closable="false" show-icon
              title="密级、访问范围、新增授权、账号权限放宽等变更须他人复核后才生效；申请人不能审批自己提交的单据。" />

    <el-table :data="visible" v-loading="loading" border stripe empty-text="没有待处理的审批单">
      <el-table-column prop="created_at" label="提交时间" width="150" />
      <el-table-column label="类型" width="120">
        <template #default="{ row }">
          <el-tag size="small" :type="kindType(row.kind)">{{ kindLabel(row.kind) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="对象" min-width="150" show-overflow-tooltip>
        <template #default="{ row }">
          <el-tag size="small" type="info" effect="plain">
            {{ row.subject_type === 'user' ? '账号' : '文档' }}
          </el-tag>
          {{ row.target || '—' }}
        </template>
      </el-table-column>
      <el-table-column prop="summary" label="变更内容" min-width="240" show-overflow-tooltip />
      <el-table-column prop="requester" label="申请人" width="110" />
      <el-table-column prop="reason" label="申请理由" min-width="160" show-overflow-tooltip />
      <el-table-column label="状态" width="110">
        <template #default="{ row }">
          <el-tag size="small" :type="statusType(row.status)">{{ statusLabel(row.status) }}</el-tag>
          <div v-if="row.status === 'pending' && row.requester === me" class="muted">本人提交</div>
        </template>
      </el-table-column>
      <el-table-column label="处理人 / 时间" width="190">
        <template #default="{ row }">
          <div>{{ row.approver || '—' }}</div>
          <div class="muted">{{ row.decided_at }}</div>
          <div v-if="row.decided_reason" class="muted" :title="row.decided_reason">{{ row.decided_reason }}</div>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="150" fixed="right">
        <template #default="{ row }">
          <template v-if="row.status === 'pending'">
            <el-button link type="primary" size="small" :disabled="row.requester === me"
                       :title="row.requester === me ? '申请人不能审批自己提交的变更申请' : ''"
                       @click="open('approve', row)">通过</el-button>
            <el-button link type="danger" size="small" :disabled="row.requester === me"
                       :title="row.requester === me ? '申请人不能审批自己提交的变更申请' : ''"
                       @click="open('reject', row)">驳回</el-button>
          </template>
          <span v-else class="muted">{{ statusLabel(row.status) }}</span>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="dlg.open" :title="dlg.mode === 'approve' ? '批准变更' : '驳回变更'" width="520px">
      <el-descriptions :column="1" border size="small">
        <el-descriptions-item label="变更内容">{{ dlg.row?.summary }}</el-descriptions-item>
        <el-descriptions-item label="申请人">{{ dlg.row?.requester }}</el-descriptions-item>
        <el-descriptions-item label="申请理由">{{ dlg.row?.reason || '—' }}</el-descriptions-item>
      </el-descriptions>
      <el-alert v-if="dlg.mode === 'approve'" class="tip" type="warning" :closable="false" show-icon
                title="批准后变更立即生效并写入审计日志，无法撤回。" />
      <el-form label-width="84px" style="margin-top:12px" @submit.prevent="submit">
        <el-form-item :label="dlg.mode === 'reject' ? '驳回理由' : '审批说明'">
          <el-input v-model="dlg.note" type="textarea" :rows="3"
                    :placeholder="dlg.mode === 'reject' ? '必填：说明驳回原因' : '选填：说明批准依据'" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dlg.open = false">取消</el-button>
        <el-button :type="dlg.mode === 'approve' ? 'primary' : 'danger'"
                   :loading="dlg.loading" @click="submit">
          {{ dlg.mode === 'approve' ? '确认批准' : '确认驳回' }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { admin } from '../api'
import { cachedUser } from '../session'

const rows = ref([])
const loading = ref(false)
const tab = ref('pending')
const me = cachedUser()?.username || ''

const pending = computed(() => rows.value.filter((r) => r.status === 'pending'))
const decided = computed(() => rows.value.filter((r) => r.status !== 'pending'))
const visible = computed(() => (tab.value === 'pending' ? pending.value : decided.value))

const kindMap = {
  clearance: { l: '密级变更', t: 'danger' },
  acl: { l: '访问范围', t: 'warning' },
  acl_grant: { l: '新增授权', t: 'primary' },
  // P0-1：账号权限放宽（加角色 / 升密 / 启用 / 改挂部门）双人复核
  user_privilege: { l: '账号权限', t: 'danger' }
}
const kindLabel = (k) => (kindMap[k] || { l: k }).l
const kindType = (k) => (kindMap[k] || { t: 'info' }).t
const statusLabel = (s) => ({ pending: '待审批', approved: '已通过', rejected: '已驳回' }[s] || s)
const statusType = (s) => ({ pending: 'warning', approved: 'success', rejected: 'danger' }[s] || 'info')

const dlg = reactive({ open: false, mode: 'approve', row: null, note: '', loading: false })

async function load() {
  loading.value = true
  try {
    rows.value = await admin.approvals()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '加载审批队列失败')
  } finally {
    loading.value = false
  }
}

function open(mode, row) {
  // 后端 decide() 同样拦截自审，这里只是提前给出可读提示，不依赖前端兜底
  if (row.requester === me) {
    ElMessage.warning('申请人不能审批自己提交的变更申请')
    return
  }
  dlg.mode = mode
  dlg.row = row
  dlg.note = ''
  dlg.open = true
}

async function submit() {
  const note = dlg.note.trim()
  if (dlg.mode === 'reject' && !note) {
    ElMessage.error('驳回必须填写理由')
    return
  }
  dlg.loading = true
  try {
    if (dlg.mode === 'approve') await admin.approve(dlg.row.id, note)
    else await admin.reject(dlg.row.id, note)
    ElMessage.success(dlg.mode === 'approve' ? '已批准，变更已生效' : '已驳回')
    dlg.open = false
    await load()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '处理失败')
  } finally {
    dlg.loading = false
  }
}

onMounted(load)
</script>

<style scoped>
.bar { display: flex; justify-content: space-between; align-items: center; }
.filters { display: flex; gap: 8px; align-items: center; }
.tip { margin: 10px 0; }
</style>
