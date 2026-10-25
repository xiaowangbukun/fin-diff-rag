// SPDX-License-Identifier: AGPL-3.0-only
// 会话存储抽象（P0-4 / P0-2）
//
// 两种会话传输模式，由服务端 AUTH_COOKIE_MODE 决定，前端不需要配置：
//   · bearer 模式（默认，兼容既有部署）：令牌放 localStorage，请求带
//     Authorization: Bearer。适合内网/受控终端，代价是 XSS 可读令牌。
//   · cookie 模式（金融机构推荐）：令牌只在 HttpOnly Cookie 里，JS 读不到；
//     写操作另带 CSRF 双提交头（X-CSRF-Token），Cookie 值由服务端下发，
//     前端只从 document.cookie 读同名非 HttpOnly 的那一份。
//
// 关键点：cookie 模式下 localStorage **不落任何令牌**，只留一个模式标志位。
// 路由守卫靠 hasSession() 判断"是否需要尝试 /auth/me"，而不是靠令牌存在。

export const TOKEN_KEY = 'finrag_token'
export const USER_KEY = 'finrag_user'
export const MODE_KEY = 'finrag_session_mode'
export const CSRF_COOKIE = 'finrag_csrf'

export function getToken() {
  return localStorage.getItem(TOKEN_KEY) || ''
}

export function sessionMode() {
  return localStorage.getItem(MODE_KEY) || (getToken() ? 'bearer' : '')
}

/** 是否存在"可能有效"的会话：有令牌，或 cookie 模式标志位。 */
export function hasSession() {
  return !!getToken() || localStorage.getItem(MODE_KEY) === 'cookie'
}

/** 登录/改密/恢复码登录成功后统一落库（res.token 为空即 cookie 模式）。 */
export function setSession(res) {
  if (!res) return
  if (res.token) {
    localStorage.setItem(TOKEN_KEY, res.token)
    localStorage.setItem(MODE_KEY, 'bearer')
  } else {
    // cookie 模式：清掉任何历史遗留的 Bearer，避免两套凭据同时存在
    localStorage.removeItem(TOKEN_KEY)
    localStorage.setItem(MODE_KEY, 'cookie')
  }
  if (res.user) localStorage.setItem(USER_KEY, JSON.stringify(res.user))
}

export function setUser(user) {
  if (user) localStorage.setItem(USER_KEY, JSON.stringify(user))
}

export function cachedUser() {
  try { return JSON.parse(localStorage.getItem(USER_KEY) || 'null') } catch (e) { return null }
}

/** 退出/401 时清干净：令牌、缓存的用户、模式标志位。 */
export function clearSession() {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
  localStorage.removeItem(MODE_KEY)
}

/** 读 CSRF Cookie（服务端刻意设为非 HttpOnly 的那一枚）。 */
export function csrfToken() {
  const hit = document.cookie.split(';').map((s) => s.trim())
    .find((s) => s.startsWith(`${CSRF_COOKIE}=`))
  return hit ? decodeURIComponent(hit.slice(CSRF_COOKIE.length + 1)) : ''
}

/** 幂等请求：GET/HEAD/OPTIONS 不需要 CSRF。 */
export function needsCsrf(method) {
  return !['get', 'head', 'options'].includes((method || 'get').toLowerCase())
}
