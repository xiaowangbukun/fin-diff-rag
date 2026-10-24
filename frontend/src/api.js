// SPDX-License-Identifier: Apache-2.0
import axios from 'axios'

const api = axios.create({ baseURL: '/api', timeout: 120000 })

api.interceptors.request.use((cfg) => {
  const t = localStorage.getItem('finrag_token')
  if (t) cfg.headers.Authorization = `Bearer ${t}`
  return cfg
})

api.interceptors.response.use(
  (r) => r.data,
  (err) => {
    const status = err.response?.status
    if (status === 401 && !location.hash.startsWith('#/login')) {
      localStorage.removeItem('finrag_token')
      localStorage.removeItem('finrag_user')
      location.hash = '#/login'
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
  depts: () => api.get('/admin/departments'),
  audit: (params) => api.get('/admin/audit', { params }),
  auditDetail: (id) => api.get(`/admin/audit/${id}`),
  stats: () => api.get('/admin/stats'),
  jigsaw: () => api.get('/admin/jigsaw'),
  // 审批中心（密级 / 访问范围 / 新增授权变更的双人复核）
  approvals: () => api.get('/admin/approvals'),
  approve: (id, reason = '') => api.post(`/admin/approvals/${id}/approve`, { reason }),
  reject: (id, reason = '') => api.post(`/admin/approvals/${id}/reject`, { reason })
}
