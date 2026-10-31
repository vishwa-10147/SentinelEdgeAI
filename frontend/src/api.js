import axios from 'axios'

// In production the console is served by the API itself, so talk to the same
// origin. The Vite dev server proxies nothing, so it points at :9000.
export const API_BASE = import.meta.env.VITE_API_BASE
  || (import.meta.env.DEV ? 'http://localhost:9000' : window.location.origin)

const CSRF = { 'X-Sentinel-CSRF': '1' }

// The access token lives only in memory; the refresh token is an HttpOnly
// cookie the page cannot read.
let accessToken = null
let refreshTimer = null
let refreshing = null
const listeners = new Set()

export function onSessionEnded(fn){
  listeners.add(fn)
  return ()=>listeners.delete(fn)
}

function endSession(){
  setToken(null)
  listeners.forEach(fn=>fn())
}

function setToken(token, expiresIn){
  accessToken = token
  if(refreshTimer) clearTimeout(refreshTimer)
  refreshTimer = null
  if(token && expiresIn){
    // renew a minute before expiry so requests never carry a dead token
    refreshTimer = setTimeout(()=>{ refreshSession().catch(endSession) }, Math.max(10, expiresIn - 60) * 1000)
  }
}

export function getAccessToken(){
  return accessToken
}

const client = axios.create({ baseURL: API_BASE, withCredentials: true })

client.interceptors.request.use(config=>{
  if(accessToken) config.headers.Authorization = `Bearer ${accessToken}`
  return config
})

client.interceptors.response.use(
  res=>res,
  async error=>{
    const config = error.config || {}
    const status = error.response?.status
    const isAuthCall = (config.url || '').startsWith('/api/auth/')
    if(status === 401 && accessToken && !config._retried && !isAuthCall){
      config._retried = true
      try{
        await refreshSession()
        return client(config)
      }catch(e){
        endSession()
      }
    }
    return Promise.reject(error)
  }
)

function accept(data){
  setToken(data.access_token, data.expires_in)
  return data.user
}

export function errorMessage(e, fallback = 'Request failed'){
  return e?.response?.data?.detail || fallback
}

export async function authStatus(){
  const res = await client.get('/api/auth/status')
  return res.data
}

export async function login(username, password, otp){
  const res = await client.post('/api/auth/login', { username, password, ...(otp ? { otp } : {}) })
  return accept(res.data)
}

export async function startMfaSetup(){
  const res = await client.post('/api/auth/mfa/setup')
  return res.data
}

export async function enableMfa(code){
  const res = await client.post('/api/auth/mfa/enable', { code })
  return res.data
}

export function refreshSession(){
  // single flight: concurrent 401s share one refresh
  if(!refreshing){
    refreshing = client.post('/api/auth/refresh', null, { headers: CSRF })
      .then(res=>accept(res.data))
      .finally(()=>{ refreshing = null })
  }
  return refreshing
}

export async function logout(){
  try{
    await client.post('/api/auth/logout', null, { headers: CSRF })
  }finally{
    setToken(null)
  }
}

export async function changePassword(currentPassword, newPassword){
  const res = await client.post('/api/auth/password', { current_password: currentPassword, new_password: newPassword })
  return res.data
}

export async function apiGet(path, fallback){
  try{
    const res = await client.get(path)
    return res.data ?? fallback
  }catch(e){
    return fallback
  }
}

export async function apiPost(path, body = {}){
  const res = await client.post(path, body)
  return res.data
}

export async function apiPatch(path, body = {}){
  const res = await client.patch(path, body)
  return res.data
}

export async function apiDelete(path){
  const res = await client.delete(path)
  return res.data
}

// WebSockets cannot send headers: connect, then authenticate with the first message.
// resume = { epoch, cursor } of the last event seen: the server replays what was missed (or says "resync")
export function openSocket(path, resume){
  const ws = new WebSocket(API_BASE.replace(/^http/, 'ws') + path)
  ws.addEventListener('open', ()=>{
    ws.send(JSON.stringify({ type: 'auth', token: accessToken || '', ...(resume && resume.epoch ? { epoch: resume.epoch, cursor: resume.cursor } : {}) }))
  })
  return ws
}

export const ROLE_RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }

export function hasRole(user, minimum){
  return (ROLE_RANK[user?.role] ?? -1) >= ROLE_RANK[minimum]
}
