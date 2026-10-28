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

      <el-divider />
      <div class="page-title">跨账号合谋检出</div>
      <div class="muted" style="margin-bottom:8px">
        同一篇文档被多个账号分别读取、并集覆盖率超过阈值时列出（只检出、不自动处置）——
        单账号账本挡不住"每人取一块、线下合并"，需人工复核后按机构流程处理。标记「近似」的条目
        是明细被截断后的上界估算，不能当作确凿证据。
      </div>
      <el-table :data="coalition" size="small" empty-text="当前无合谋疑点">
        <el-table-column label="文档" min-width="200" show-overflow-tooltip>
          <template #default="{ row }">
            {{ row.doc_title }}
            <el-tag v-if="row.approx" size="small" type="info">近似</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="参与账号" width="90">
          <template #default="{ row }">{{ row.users }} 个</template>
        </el-table-column>
        <el-table-column label="并集覆盖" width="95">
          <template #default="{ row }">{{ row.union_seen }}/{{ row.total }} 段</template>
        </el-table-column>
        <el-table-column label="覆盖率" width="140">
          <template #default="{ row }">
            <el-progress :percentage="Math.round(row.coverage * 100)" color="#c0392b" :stroke-width="10" />
          </template>
        </el-table-column>
        <el-table-column label="成员（按披露量）" min-width="240" show-overflow-tooltip>
          <template #default="{ row }">
            {{ row.members.map(m => `${m.username} ${m.seen}段`).join('、') }}
          </template>
        </el-table-column>
      </el-table>

      <el-divider />
      <div class="page-title">原件审查</div>
      <div class="muted" style="margin-bottom:8px">
        仅当服务端开启原件留存（ORIGINAL_STORE_ENABLED）时才有原件可查：上传原文会另存对象存储，
        台账记录每个版本的 sha256 与体积。下载前服务端会重算哈希，与台账不一致即拒发（409）——
        这正是"原件被替换/损坏"的检出点。密级不够的账号一律看不到（含管理员）。
      </div>
      <div style="display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap">
        <el-input v-model="orig.docId" placeholder="文档 ID（从文档列表复制）" style="width:320px" />
        <el-button @click="loadOriginals">查台账</el-button>
        <el-button :disabled="!orig.rows.length" @click="verifyOriginals">完整性复核</el-button>
        <span v-if="orig.checked" class="muted">核对时间：{{ orig.checked }}</span>
      </div>
      <el-table :data="orig.rows" size="small" empty-text="未查询或无版本记录">
        <el-table-column label="版本" width="90">
          <template #default="{ row }">
            v{{ row.version }}
            <el-tag v-if="row.is_current" size="small" type="success">当前</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="原件" width="90">
          <template #default="{ row }">
            <el-tag :type="row.stored ? 'success' : 'info'" size="small">
              {{ row.stored ? '已留存' : '缺失' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="体积" width="100">
          <template #default="{ row }">{{ row.size }} B</template>
        </el-table-column>
        <el-table-column label="sha256" min-width="220" show-overflow-tooltip>
          <template #default="{ row }">{{ row.sha256 || '—' }}</template>
        </el-table-column>
        <el-table-column label="写入时间" width="170">
          <template #default="{ row }">{{ row.stored_at || '—' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="110">
          <template #default="{ row }">
            <el-button link type="primary" :disabled="!row.stored"
                       @click="downloadOriginal(row.version)">下载</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div v-if="orig.enabled === false" class="muted" style="margin-top:6px">
        原件留存当前未启用：上传原文解析完即删，库内只有切片文本。
      </div>
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
const coalition = ref([])
// 原件审查：台账只读展示；下载走服务端流式下发（前端不拼对象存储地址）
const orig = reactive({ docId: '', rows: [], enabled: null, checked: '' })

async function loadOriginals() {
  const id = orig.docId.trim()
  if (!id) { ElMessage.warning('请先填写文档 ID'); return }
  try {
    const res = await admin.originalMeta(id)
    orig.rows = res.items || []
    orig.enabled = res.enabled
    orig.checked = res.checked_at || ''
    if (!orig.rows.length) ElMessage.info('该文档没有版本记录')
  } catch (e) {
    orig.rows = []
    ElMessage.error(e.response?.data?.detail || '查询失败')
  }
}

async function verifyOriginals() {
  try {
    const res = await admin.verifyOriginal(orig.docId.trim())
    orig.checked = res.checked_at || ''
    if (res.ok) {
      ElMessage.success(`原件完整（v${res.version}，${res.size} B，sha256 与台账一致）`)
    } else {
      ElMessage.error(`复核不一致：${res.reason || '原件与台账哈希不符'}`)
    }
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '复核失败')
  }
}

async function downloadOriginal(version) {
  const id = orig.docId.trim()
  try {
    const blob = await admin.downloadOriginal(id, version)
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${id}_v${version}_original.bin`
    a.click()
    URL.revokeObjectURL(url)
    ElMessage.success('已下载（本次下载已记审计）')
  } catch (e) {
    // 409 = 台账有原件但取不到/哈希不符，属于必须人工介入的状态冲突。
    // responseType=blob 时错误体也是 Blob，要读出来才能看到 detail。
    let detail = e.response?.data?.detail
    if (!detail && e.response?.data instanceof Blob) {
      try { detail = JSON.parse(await e.response.data.text()).detail } catch { /* 非 JSON 错误体 */ }
    }
    ElMessage.error(detail || '下载失败')
  }
}

async function loadBoard() {
  try { board.value = await admin.jigsaw() } catch (e) { /* 非管理员忽略 */ }
  try { coalition.value = await admin.coalition() } catch (e) { /* 同上 */ }
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
