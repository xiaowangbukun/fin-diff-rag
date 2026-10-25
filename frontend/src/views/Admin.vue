<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<template>
  <div>
    <div class="bar">
      <div class="page-title">用户与权限</div>
      <el-button type="primary" @click="open()">新建用户</el-button>
    </div>
    <el-table :data="rows" border stripe>
      <el-table-column prop="username" label="账号" width="120" />
      <el-table-column prop="display_name" label="姓名" width="110" />
      <el-table-column prop="dept_name" label="部门" width="130" />
      <el-table-column label="角色" width="180">
        <template #default="{ row }">
          <el-tag v-for="r in row.roles" :key="r" size="small" style="margin-right:4px">{{ r }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="密级" width="110">
        <template #default="{ row }">
          <el-tag size="small" :type="levelType(row.clearance)">{{ row.clearance_name }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="80">
        <template #default="{ row }">
          <el-tag size="small" :type="row.status ? 'success' : 'info'">{{ row.status ? '启用' : '停用' }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="ID" width="300">
        <template #default="{ row }"><code class="uid">{{ row.id }}</code></template>
      </el-table-column>
      <el-table-column label="操作" width="300">
        <template #default="{ row }">
          <el-button link type="primary" @click="open(row)">编辑</el-button>
          <el-popconfirm title="重置后该账号需重新绑定动态口令，且其所有会话立即失效。确认？"
                         @confirm="resetMfa(row)">
            <template #reference>
              <el-button link type="warning">重置动态口令</el-button>
            </template>
          </el-popconfirm>
          <!-- P0-4：强制下线（口令疑似泄露/人员交接时的止血动作） -->
          <el-popconfirm title="将立即吊销该账号全部会话（已签发的令牌同时失效）。确认？"
                         @confirm="kickSessions(row)">
            <template #reference>
              <el-button link type="danger">强制下线</el-button>
            </template>
          </el-popconfirm>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="dlg.open" :title="dlg.form.id ? '编辑用户' : '新建用户'" width="520">
      <el-form label-width="90px">
        <el-form-item label="账号"><el-input v-model="dlg.form.username" :disabled="!!dlg.form.id" /></el-form-item>
        <el-form-item label="姓名"><el-input v-model="dlg.form.display_name" /></el-form-item>
        <el-form-item label="密码"><el-input v-model="dlg.form.password" placeholder="留空表示不修改" show-password /></el-form-item>
        <el-form-item label="部门">
          <el-select v-model="dlg.form.dept_id" clearable style="width:100%">
            <el-option v-for="d in depts" :key="d.id" :label="d.name" :value="d.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="角色">
          <el-checkbox-group v-model="dlg.form.roles">
            <el-checkbox v-for="r in roles" :key="r" :label="r" :value="r" />
          </el-checkbox-group>
        </el-form-item>
        <el-form-item label="密级">
          <el-select v-model="dlg.form.clearance">
            <el-option v-for="l in levels" :key="l.value" :label="l.label" :value="l.value" />
          </el-select>
        </el-form-item>
        <el-form-item label="启用"><el-switch v-model="dlg.form.status" /></el-form-item>
        <el-form-item label="变更理由">
          <el-input v-model="dlg.form.reason" type="textarea" :rows="2"
                    placeholder="必填建议：权限放宽须另一名管理员复核，复核人会看这条理由" />
        </el-form-item>
      </el-form>
      <el-alert class="tip" type="warning" :closable="false" show-icon
                title="加角色 / 升密 / 停用→启用 / 改挂部门属于权限放宽，会进入审批队列由他人复核；降密、撤角色、停用即时生效。" />
      <template #footer>
        <el-button @click="dlg.open = false">取消</el-button>
        <el-button type="primary" @click="save">保存</el-button>
      </template>
    </el-dialog>

      <el-divider />
      <div class="page-title">防拼图风险榜</div>
      <div class="muted" style="margin-bottom:8px">
        按累积披露比例排序——同一用户对同一文档的披露比例越高，越可能正在用多轮提问把全貌拼出来。
      </div>
      <el-table :data="board" size="small" empty-text="当前无高风险组合">
        <el-table-column label="用户" min-width="100">
          <template #default="{ row }"><b>{{ row.username }}</b></template>
        </el-table-column>
        <el-table-column label="文档" min-width="220" show-overflow-tooltip>
          <template #default="{ row }">
            {{ row.doc_title }}
            <el-tag size="small" :type="row.clearance_name === '绝密' ? 'danger' : 'warning'">
              {{ row.clearance_name }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="已披露" width="100">
          <template #default="{ row }">{{ row.seen }}/{{ row.total }} 段</template>
        </el-table-column>
        <el-table-column label="覆盖率" width="140">
          <template #default="{ row }">
            <el-progress :percentage="Math.round(row.coverage * 100)"
              :color="row.risk === 'high' ? '#c0392b' : '#e6a23c'" :stroke-width="10" />
          </template>
        </el-table-column>
        <el-table-column label="全文读取" width="90">
          <template #default="{ row }">{{ row.full_reads }} 次</template>
        </el-table-column>
        <el-table-column label="风险" width="70">
          <template #default="{ row }">
            <el-tag size="small" :type="row.risk === 'high' ? 'danger' : 'warning'">
              {{ row.risk === 'high' ? '高' : '中' }}
            </el-tag>
          </template>
        </el-table-column>
      </el-table>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { admin, docs } from '../api'

const rows = ref([])
const depts = ref([])
const roles = ref([])
const levels = ref([])
const board = ref([])

async function loadBoard() {
  try { board.value = await admin.jigsaw() } catch (e) { /* 非管理员忽略 */ }
}
const dlg = reactive({ open: false, form: { id: '', username: '', display_name: '', password: '', dept_id: '', roles: [], clearance: 1, status: true, reason: '' } })
const levelType = (c) => ({ 0: 'success', 1: 'info', 2: 'warning', 3: 'danger' }[c] || 'info')

async function load() {
  rows.value = await admin.users()
  depts.value = await admin.depts()
  const m = await docs.meta()
  roles.value = m.roles
  levels.value = m.levels
}

function open(row) {
  dlg.form = row
    ? { id: row.id, username: row.username, display_name: row.display_name, password: '', dept_id: row.dept_id, roles: [...row.roles], clearance: row.clearance, status: row.status, reason: '' }
    : { id: '', username: '', display_name: '', password: 'User@123', dept_id: '', roles: ['guest'], clearance: 1, status: true, reason: '' }
  dlg.open = true
}

async function save() {
  try {
    const p = { ...dlg.form }
    if (dlg.form.id) {
      const res = await admin.updateUser(dlg.form.id, p)
      // P0-1：放宽类变更不会立即生效，服务端返回待审单信息
      const ap = res?.approval
      if (ap?.pending) {
        ElMessage.warning(`权限放宽已提交审批（单号 ${ap.id}），复核通过后才生效`)
      } else {
        ElMessage.success('已保存（收紧类变更即时生效）')
      }
    } else {
      await admin.createUser(p)
      ElMessage.success('已创建（首次登录须改密，初始授权已写入审批记录）')
    }
    dlg.open = false
    await load()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '保存失败')
  }
}

async function kickSessions(row) {
  try {
    const res = await admin.revokeSessions(row.id)
    ElMessage.success(`已强制下线 ${res.revoked ?? 0} 个会话`)
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '操作失败')
  }
}

async function resetMfa(row) {
  try {
    const res = await admin.resetMfa(row.id)
    ElMessage.success(res.was_enrolled
      ? '已清除该账号的动态口令，其会话已全部失效'
      : '已清除待绑定的动态口令密钥')
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '重置失败')
  }
}

onMounted(() => { load(); loadBoard() })
</script>

<style scoped>
.bar { display: flex; justify-content: space-between; align-items: center; }
.uid { font-size: 11px; color: #8a94a6; }
</style>
