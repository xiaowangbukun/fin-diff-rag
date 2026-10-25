<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<template>
  <el-dialog :model-value="modelValue" title="一次性恢复码（请立即保存）" width="460px"
             :close-on-click-modal="false" :show-close="false"
             @update:model-value="$emit('update:modelValue', $event)">
    <el-alert type="warning" :closable="false" show-icon
              title="这组码只显示这一次。请打印或存入密码管理器；每个码仅能登录一次。" />
    <div class="hint">格式 XXXX-XXXX-XXXX；登录时可忽略大小写、空格与连字符。</div>
    <ol class="list">
      <li v-for="c in codes" :key="c"><code>{{ c }}</code></li>
    </ol>
    <template #footer>
      <el-button @click="copy">复制</el-button>
      <el-button @click="download">下载 TXT</el-button>
      <el-button type="primary" @click="close">我已保存</el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ElMessage } from 'element-plus'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  codes: { type: Array, default: () => [] }
})
const emit = defineEmits(['update:modelValue', 'saved'])

async function copy() {
  try {
    await navigator.clipboard.writeText(props.codes.join('\n'))
    ElMessage.success('已复制到剪贴板')
  } catch (e) {
    ElMessage.error('复制失败，请手动选择文本')
  }
}

function download() {
  const body = 'FinRAG 一次性恢复码（每个仅可使用一次）\n'
    + '生成时间：' + new Date().toLocaleString() + '\n\n'
    + props.codes.join('\n') + '\n'
  const url = URL.createObjectURL(new Blob([body], { type: 'text/plain;charset=utf-8' }))
  const a = document.createElement('a')
  a.href = url
  a.download = 'finrag-recovery-codes.txt'
  a.click()
  URL.revokeObjectURL(url)
}

function close() {
  emit('update:modelValue', false)
  emit('saved')
}
</script>

<style scoped>
.hint { margin-top: 8px; font-size: 12px; color: #8a94a6; }
.list { margin: 12px 0 0; padding-left: 22px; font-family: Consolas, monospace;
  font-size: 15px; letter-spacing: 1px; line-height: 1.9; color: #16457e; }
</style>
