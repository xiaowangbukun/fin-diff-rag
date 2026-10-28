// SPDX-License-Identifier: AGPL-3.0-only
import axios from 'axios'
import { clearSession, csrfToken, getToken, needsCsrf } from './session'

const api = axios.create({
  baseURL: '/api',
  timeout: 120000,
  // cookie 模式下会话随 Cookie 走；跨域白名单部署时也必须带上凭据
  withCredentials: true
})

api.interceptors.request.use((cfg) => {
  // bearer 模式：内存里只有令牌本身；cookie 模式没有令牌可带（HttpOnly）
  const t = getToken()
  if (t) cfg.headers.Authorization = `Bearer ${t}`
  // 双提交 CSRF：写操作必须让 Cookie 与请求头一致，服务端才放行。
  // 预检/跨域请求也会被浏览器带上（X-CSRF-Token 已在 CORS 允许头里）。
  if (needsCsrf(cfg.method)) {
    const csrf = csrfToken()
    if (csrf) cfg.headers['X-CSRF-Token'] = csrf
  }
  return cfg
})

api.interceptors.response.use(
  (r) => r.data,
  (err) => {
    const status = err.response?.status
    if (status === 401 && !location.hash.startsWith('#/login')) {
      // 会话已失效（空闲超时 / 被吊销 / 令牌过期）：清干净再回登录页
      clearSession()
      location.hash = '#/login'
      location.reload()
    }
    return Promise.reject(err)
  }
)

export default api

export const auth = {
  login: (username, password) => api.post('/auth/login', { username, password }),
  // 第二步：口令通过后凭挑战票据 + 动态口令（或一次性恢复码）换正式会话
  loginMfa: (challenge, code, recoveryCode = '') =>
    api.post('/auth/login/mfa', { challenge, code, recovery_code: recoveryCode }),
  providers: () => api.get('/auth/providers'),
  me: () => api.get('/auth/me'),
  logout: () => api.post('/auth/logout'),
  // P0-4：退出全部设备 / 查看与吊销单个设备会话
  logoutAll: () => api.post('/auth/logout/all'),
  sessions: () => api.get('/auth/sessions'),
  revokeSession: (sid) => api.post(`/auth/sessions/${encodeURIComponent(sid)}/revoke`),
  changePassword: (oldPassword, newPassword) =>
    api.post('/auth/change-password', { old_password: oldPassword, new_password: newPassword }),
  // 动态口令：绑定/确认/解绑都必须带上当前口令（二次认证）
  totpSetup: (password) => api.post('/auth/totp/setup', { password }),
  totpConfirm: (code) => api.post('/auth/totp/confirm', { code }),
  totpDisable: (password) => api.post('/auth/totp/disable', { password }),
  // 恢复码：重新生成会让旧的一整组立即作废，明文只返回这一次
  regenerateRecoveryCodes: (password) =>
    api.post('/auth/recovery-codes/regenerate', { password }),
  // SSO 回调种下的 HttpOnly 交接票据 → 正式会话（withCredentials 才会带 cookie）
  ssoSession: () => api.post('/auth/oidc/session', {}, { withCredentials: true })
}

export const docs = {
  meta: () => api.get('/docs/meta'),
  list: () => api.get('/docs'),
  create: (data) => api.post('/docs', data),
  upload: (form) => api.post('/docs/upload', form, { headers: { 'Content-Type': 'multipart/form-data' } }),
  get: (id) => api.get(`/docs/${id}`),
  update: (id, data) => api.patch(`/docs/${id}`, data),
  remove: (id) => api.delete(`/docs/${id}`),
  addAcl: (id, data) => api.post(`/docs/${id}/acl`, data),
  delAcl: (id, aclId) => api.delete(`/docs/${id}/acl/${aclId}`),
  pii: (id) => api.get(`/docs/${id}/pii`)
}

export const chat = {
  ask: (query, top_k) => api.post('/chat', { query, top_k })
}

export const admin = {
  users: () => api.get('/admin/users'),
  createUser: (data) => api.post('/admin/users', data),
  updateUser: (id, data) => api.patch(`/admin/users/${id}`, data),
  resetMfa: (id) => api.post(`/admin/users/${id}/mfa-reset`),
  // P0-4：管理员强制下线某账号的全部设备（口令泄露/离职交接时用）
  revokeSessions: (id) => api.post(`/admin/users/${id}/revoke-sessions`),
  depts: () => api.get('/admin/departments'),
  audit: (params) => api.get('/admin/audit', { params }),
  auditDetail: (id) => api.get(`/admin/audit/${id}`),
  stats: () => api.get('/admin/stats'),
  jigsaw: () => api.get('/admin/jigsaw'),
  // 跨账号合谋拼图检出（多账号各取一块线下合并；只读，交人工复核）
  coalition: () => api.get('/admin/jigsaw/coalition'),
  // 审批中心（密级 / 访问范围 / 新增授权 / 账号权限变更的双人复核）
  approvals: () => api.get('/admin/approvals'),
  approve: (id, reason = '') => api.post(`/admin/approvals/${id}/approve`, { reason }),
  reject: (id, reason = '') => api.post(`/admin/approvals/${id}/reject`, { reason }),
  // 原件审查（ORIGINAL_STORE_ENABLED 时才有原件）：台账 / 下载 / 完整性复核。
  // 下载走 blob（服务端逐次留痕，不给预签名地址），失败原因见 409 的 detail。
  originalMeta: (docId) => api.get(`/admin/documents/${docId}/original/meta`),
  downloadOriginal: (docId, version) =>
    api.get(`/admin/documents/${docId}/original`, {
      params: version ? { version } : {},
      responseType: 'blob'
    }),
  verifyOriginal: (docId, version) =>
    api.post(`/admin/documents/${docId}/original/verify`, {},
      { params: version ? { version } : {} })
}
