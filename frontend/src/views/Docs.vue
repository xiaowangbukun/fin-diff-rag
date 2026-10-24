<!-- SPDX-License-Identifier: Apache-2.0 -->
<template>
  <div>
    <div class="bar">
      <div class="page-title">知识库管理（仅展示您有权访问的文档）</div>
      <div>
        <el-button @click="load">刷新</el-button>
        <el-button type="primary" @click="up.open = true">录入 / 上传</el-button>
      </div>
    </div>

    <el-table :data="rows" border stripe>
      <el-table-column prop="title" label="文档标题" min-width="220" />
      <el-table-column label="密级" width="150">
        <template #default="{ row }">
          <el-tag size="small" :type="levelType(row.clearance)">{{ row.clearance_name }}</el-tag>
          <el-tooltip v-if="row.max_chunk_clearance != null && row.max_chunk_clearance > row.clearance"
            content="该文档存在更高密级的切片，已按切片级权限隔离（同文档跨密级）" placement="top">
            <el-tag size="small" type="danger" style="margin-left:4px">含{{ levelName(row.max_chunk_clearance) }}段</el-tag>
          </el-tooltip>
          <el-tooltip v-if="row.parse_quality === 'low'"
            content="该文档解析质量偏低（疑似乱码或版式异常），检索与问答前建议核对原文" placement="top">
            <el-tag size="small" type="warning" style="margin-left:4px">解析质量低</el-tag>
          </el-tooltip>
          <el-tooltip v-else-if="row.parse_quality === 'ocr'"
            content="该文档为扫描件 OCR 识别结果，关键数字与条款建议核对原文" placement="top">
            <el-tag size="small" type="info" style="margin-left:4px">OCR</el-tag>
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column label="可见范围" width="150">
        <template #default="{ row }">
          <span>{{ modeLabel(row.acl_mode) }}</span>
          <div class="muted" v-if="row.acl.length">+{{ row.acl.length }} 条授权</div>
        </template>
      </el-table-column>
      <el-table-column prop="owner_dept" label="归属部门" width="130" />
      <el-table-column prop="chunk_count" label="切片" width="70" />
      <el-table-column label="敏感信息" width="100">
        <template #default="{ row }">
          <el-tag v-if="row.pii_hits" size="small" type="danger">{{ row.pii_hits }} 处</el-tag>
          <span v-else class="muted">无</span>
        </template>
      </el-table-column>
      <el-table-column prop="created_at" label="录入时间" width="140" />
      <el-table-column label="操作" width="230">
        <template #default="{ row }">
          <el-button link type="primary" @click="view(row)">切片</el-button>
          <el-button link type="warning" @click="openAcl(row)">授权</el-button>
          <el-button link @click="edit(row)">改密级</el-button>
          <el-button link type="danger" @click="del(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- 录入 -->
    <el-dialog v-model="up.open" title="录入知识" width="640">
      <el-tabs v-model="up.tab">
        <el-tab-pane label="文件上传" name="file">
          <el-upload drag :auto-upload="false" :limit="1" :on-change="onFile" accept=".pdf,.docx,.doc,.xlsx,.xls,.csv,.md,.txt">
            <div class="muted">将文件拖到此处，或点击选择（PDF / Word / Excel / Markdown / TXT）</div>
          </el-upload>
        </el-tab-pane>
        <el-tab-pane label="文本粘贴" name="text">
          <el-input v-model="up.content" type="textarea" :rows="8" placeholder="粘贴正文内容" />
        </el-tab-pane>
      </el-tabs>
      <el-form label-width="90px" style="margin-top:14px">
        <el-form-item label="标题"><el-input v-model="up.title" /></el-form-item>
        <el-form-item label="密级">
          <el-select v-model="up.clearance"><el-option v-for="l in meta.levels" :key="l.value" :label="l.label" :value="l.value" /></el-select>
          <span class="muted" style="margin-left:10px">不得高于您自身的密级</span>
        </el-form-item>
        <el-form-item label="可见范围">
          <el-select v-model="up.acl_mode">
            <el-option v-for="m in meta.acl_modes" :key="m.value" :label="m.label" :value="m.value" />
          </el-select>
        </el-form-item>
        <el-form-item label="归属部门">
          <el-select v-model="up.owner_dept_id" clearable>
            <el-option v-for="d in meta.departments" :key="d.id" :label="d.name" :value="d.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="标签"><el-input v-model="up.tags" placeholder="逗号分隔" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="up.open = false">取消</el-button>
        <el-button type="primary" :loading="up.loading" @click="submitUp">提交入库</el-button>
      </template>
    </el-dialog>

    <!-- 切片 -->
    <el-drawer v-model="ch.open" :title="ch.title" size="55%">
      <div v-for="c in ch.items" :key="c.id" class="chunk">
        <div class="ci">#{{ c.seq + 1 }} · {{ c.content.length }} 字</div>
        <div class="cc">{{ c.content }}</div>
      </div>
      <el-empty v-if="!ch.items.length" description="无切片" />
    </el-drawer>

    <!-- 授权 -->
    <el-drawer v-model="acl.open" :title="`授权管理 · ${acl.title}`" size="45%">
      <div class="muted" style="margin-bottom:8px">当前文档密级：{{ acl.clearance_name }} / 可见范围：{{ modeLabel(acl.acl_mode) }}</div>
      <el-table :data="acl.items" size="small" border>
        <el-table-column label="类型" width="90">
          <template #default="{ row }">{{ subjLabel(row.subject_type) }}</template>
        </el-table-column>
        <el-table-column prop="subject_key" label="对象" />
        <el-table-column label="效果" width="90">
          <template #default="{ row }">
            <el-tag size="small" :type="row.effect === 'allow' ? 'success' : 'danger'">
              {{ row.effect === 'allow' ? '允许' : '拒绝' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="80">
          <template #default="{ row }">
            <el-button link type="danger" @click="delAcl(row)">移除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-divider />
      <div class="add">
        <el-select v-model="acl.form.subject_type" style="width:110px">
          <el-option label="用户" value="user" /><el-option label="部门" value="dept" /><el-option label="角色" value="role" />
        </el-select>
        <el-select v-if="acl.form.subject_type === 'role'" v-model="acl.form.subject_key" style="width:150px">
          <el-option v-for="r in meta.roles" :key="r" :label="r" :value="r" />
        </el-select>
        <el-select v-else-if="acl.form.subject_type === 'dept'" v-model="acl.form.subject_key" style="width:180px">
          <el-option v-for="d in meta.departments" :key="d.id" :label="d.name" :value="d.id" />
        </el-select>
        <el-input v-else v-model="acl.form.subject_key" placeholder="用户ID（可在用户管理复制）" style="width:280px" />
        <el-select v-model="acl.form.effect" style="width:100px">
          <el-option label="允许" value="allow" /><el-option label="拒绝" value="deny" />
        </el-select>
        <el-button type="primary" @click="addAcl">添加</el-button>
      </div>
      <div class="muted" style="margin-top:10px">拒绝（deny）永远优先于允许；密级不足时无论授权一律不可见。</div>
    </el-drawer>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { docs } from '../api'

const rows = ref([])
const meta = ref({ levels: [], roles: [], departments: [], acl_modes: [] })

const levelType = (c) => ({ 0: 'success', 1: 'info', 2: 'warning', 3: 'danger' }[c] || 'info')
const levelName = (c) => ({ 0: '公开', 1: '内部', 2: '机密', 3: '绝密' }[c] || '未知')
const modeLabel = (m) => ({ open: '全公司可见', dept: '归属部门可见', restrict: '仅白名单可见' }[m] || m)
const subjLabel = (t) => ({ user: '用户', dept: '部门', role: '角色' }[t] || t)

const up = reactive({ open: false, tab: 'file', title: '', content: '', clearance: 1, acl_mode: 'dept', owner_dept_id: '', tags: '', file: null, loading: false })
const ch = reactive({ open: false, title: '', items: [] })
const acl = reactive({ open: false, title: '', clearance_name: '', acl_mode: '', doc_id: '', items: [], form: { subject_type: 'role', subject_key: '', effect: 'allow' } })

const onFile = (f) => { up.file = f.raw; if (!up.title) up.title = f.name }

async function load() {
  rows.value = await docs.list()
  meta.value = await docs.meta()
}

async function submitUp() {
  if (!up.title) return ElMessage.warning('请填写标题')
  up.loading = true
  try {
    if (up.tab === 'file') {
      if (!up.file) return ElMessage.warning('请选择文件')
      const fd = new FormData()
      fd.append('file', up.file)
      fd.append('title', up.title)
      fd.append('clearance', up.clearance)
      fd.append('acl_mode', up.acl_mode)
      fd.append('owner_dept_id', up.owner_dept_id || '')
      fd.append('tags', up.tags)
      await docs.upload(fd)
    } else {
      if (!up.content.trim()) return ElMessage.warning('请填写正文')
      await docs.create({ title: up.title, content: up.content, clearance: up.clearance, acl_mode: up.acl_mode, owner_dept_id: up.owner_dept_id || null, tags: up.tags })
    }
    ElMessage.success('入库完成')
    up.open = false
    up.file = null; up.content = ''; up.title = ''
    await load()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '入库失败')
  } finally { up.loading = false }
}

async function view(row) {
  const d = await docs.get(row.id)
  ch.title = d.title
  ch.items = d.chunks || []
  ch.open = true
}

async function openAcl(row) {
  acl.doc_id = row.id; acl.title = row.title; acl.clearance_name = row.clearance_name
  acl.acl_mode = row.acl_mode; acl.items = row.acl || []
  acl.form = { subject_type: 'role', subject_key: '', effect: 'allow' }
  acl.open = true
}

async function addAcl() {
  if (!acl.form.subject_key) return ElMessage.warning('请选择或填写授权对象')
  try {
    const d = await docs.addAcl(acl.doc_id, { ...acl.form })
    acl.items = d.acl
    await load()
    ElMessage.success('已添加')
  } catch (e) { ElMessage.error(e.response?.data?.detail || '操作失败') }
}

async function delAcl(row) {
  const d = await docs.delAcl(acl.doc_id, row.id)
  acl.items = d.acl
  await load()
}

async function edit(row) {
  try {
    const { value } = await ElMessageBox.prompt('新的密级（0公开 / 1内部 / 2机密 / 3绝密）', '修改密级', {
      inputValue: String(row.clearance), inputPattern: /^[0-3]$/, inputErrorMessage: '请输入 0-3'
    })
    await docs.update(row.id, { clearance: Number(value) })
    ElMessage.success('已更新')
    await load()
  } catch (e) { if (e !== 'cancel') ElMessage.error(e.response?.data?.detail || '操作失败') }
}

async function del(row) {
  try {
    await ElMessageBox.confirm(`确认删除《${row.title}》？该操作不可恢复`, '删除确认', { type: 'warning' })
    await docs.remove(row.id)
    ElMessage.success('已删除')
    await load()
  } catch (e) { if (e !== 'cancel') ElMessage.error(e.response?.data?.detail || '删除失败') }
}

onMounted(load)
</script>

<style scoped>
.bar { display: flex; justify-content: space-between; align-items: center; }
.chunk { border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; margin-bottom: 10px; background: #fbfcfe; }
.ci { font-size: 12px; color: #98a4b6; margin-bottom: 6px; }
.cc { font-size: 13px; line-height: 1.85; white-space: pre-wrap; }
.add { display: flex; gap: 8px; align-items: center; }
</style>
