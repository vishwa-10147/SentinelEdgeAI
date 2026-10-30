import React, { useCallback, useEffect, useState } from 'react'
import { apiDelete, apiGet, apiPatch, apiPost, errorMessage } from '../api'

const ROLES = ['viewer', 'analyst', 'operator', 'admin']
const ROLE_HELP = {
  viewer: 'See alerts, devices and reports',
  analyst: 'Viewer + investigate and explain alerts',
  operator: 'Analyst + block, unblock, whitelist, run demos',
  admin: 'Operator + firewall policy and user management'
}

function formatDate(ts){
  return ts ? new Date(ts * 1000).toLocaleString() : 'never'
}

export default function UsersModal({ open, onClose, currentUser }){
  const [users, setUsers] = useState([])
  const [tokens, setTokens] = useState([])
  const [tokenForm, setTokenForm] = useState({ name: '', role: 'viewer', expires_days: 90 })
  const [newToken, setNewToken] = useState(null)
  const [copied, setCopied] = useState(false)
  const [form, setForm] = useState({ username: '', password: '', role: 'viewer' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async ()=>{
    setUsers(await apiGet('/api/users', []))
    setTokens(await apiGet('/api/tokens', []))
  }, [])

  useEffect(()=>{ if(open) load() }, [open, load])

  const run = async (fn)=>{
    setBusy(true)
    setError('')
    try{
      await fn()
      await load()
    }catch(e){
      setError(errorMessage(e))
    }finally{
      setBusy(false)
    }
  }

  if(!open) return null

  const create = (event)=>{
    event.preventDefault()
    run(async ()=>{
      await apiPost('/api/users', { ...form, must_change_password: true })
      setForm({ username: '', password: '', role: 'viewer' })
    })
  }

  const createToken = (event)=>{
    event.preventDefault()
    run(async ()=>{
      const token = await apiPost('/api/tokens', { ...tokenForm, expires_days: Number(tokenForm.expires_days) })
      setNewToken(token)
      setCopied(false)
      setTokenForm({ name: '', role: 'viewer', expires_days: 90 })
    })
  }

  const copyToken = async ()=>{
    try{
      await navigator.clipboard.writeText(newToken.token)
      setCopied(true)
    }catch(e){
      setError('Copy failed; select the token and copy it by hand')
    }
  }

  const revokeToken = (t)=>{
    if(window.confirm(`Revoke token "${t.name}"? Anything using it stops working immediately.`)){
      run(()=>apiDelete(`/api/tokens/${encodeURIComponent(t.id)}`))
    }
  }

  const tokenState = (t)=>t.revoked ? 'Revoked' : t.expired ? 'Expired' : 'Active'

  const resetPassword = (username)=>{
    const password = window.prompt(`Temporary password for ${username} (at least 12 characters). They must change it at next sign-in.`)
    if(password) run(()=>apiPatch(`/api/users/${encodeURIComponent(username)}`, { password }))
  }

  const resetMfa = (username)=>{
    if(window.confirm(`Remove two-step sign-in for ${username}? Use this when they lost their phone. They are signed out and set it up again at next sign-in.`)){
      run(()=>apiPatch(`/api/users/${encodeURIComponent(username)}`, { reset_mfa: true }))
    }
  }

  const remove = (username)=>{
    if(window.confirm(`Delete user ${username}? This signs them out everywhere.`)){
      run(()=>apiDelete(`/api/users/${encodeURIComponent(username)}`))
    }
  }

  return (
    <div className="modal-backdrop">
      <section className="firewall-modal users-modal" role="dialog" aria-label="Users">
        <div className="modal-header">
          <div>
            <h2>Users</h2>
            <p>Every change takes effect immediately, including on open sessions.</p>
          </div>
          <button className="icon-button" onClick={onClose}>Close</button>
        </div>
        {error && <div className="auth-error users-error" role="alert">{error}</div>}
        <div className="rules-section">
          <div className="users-table">
            <div className="users-row users-head">
              <span>User</span><span>Role</span><span>Status</span><span>Two-step</span><span>Last sign-in</span><span />
            </div>
            {users.map(u=>{
              const self = u.username.toLowerCase() === currentUser?.username?.toLowerCase()
              return (
                <div className="users-row" key={u.username}>
                  <span>{u.username}{self && <em> (you)</em>}</span>
                  <span>
                    <select value={u.role} disabled={busy || self} onChange={e=>run(()=>apiPatch(`/api/users/${encodeURIComponent(u.username)}`, { role: e.target.value }))}>
                      {ROLES.map(r=><option key={r} value={r}>{r}</option>)}
                    </select>
                  </span>
                  <span>{u.disabled ? 'Disabled' : u.locked ? 'Locked' : u.must_change_password ? 'Must change password' : 'Active'}</span>
                  <span className={u.mfa_enabled ? 'mfa-on' : u.mfa_setup_required ? 'mfa-pending' : 'mfa-off'}>
                    {u.mfa_enabled ? 'On' : u.mfa_setup_required ? 'Setup pending' : 'Off'}
                  </span>
                  <span>{formatDate(u.last_login)}</span>
                  <span className="users-actions">
                    <button className="ghost-button" disabled={busy} onClick={()=>resetPassword(u.username)}>Reset password</button>
                    {u.mfa_enabled && <button className="ghost-button" disabled={busy} onClick={()=>resetMfa(u.username)}>Reset MFA</button>}
                    <button className="ghost-button" disabled={busy || self} onClick={()=>run(()=>apiPatch(`/api/users/${encodeURIComponent(u.username)}`, { disabled: !u.disabled }))}>
                      {u.disabled ? 'Enable' : 'Disable'}
                    </button>
                    <button className="ghost-button" disabled={busy || self} onClick={()=>remove(u.username)}>Delete</button>
                  </span>
                </div>
              )
            })}
          </div>
        </div>
        <form className="rules-section users-create" onSubmit={create}>
          <h3>Add user</h3>
          <input placeholder="Username" autoComplete="off" value={form.username} onChange={e=>setForm({ ...form, username: e.target.value })} />
          <input placeholder="Temporary password (12+ characters)" type="password" autoComplete="new-password" value={form.password} onChange={e=>setForm({ ...form, password: e.target.value })} />
          <select value={form.role} onChange={e=>setForm({ ...form, role: e.target.value })}>
            {ROLES.map(r=><option key={r} value={r}>{r}</option>)}
          </select>
          <button className="primary-button" type="submit" disabled={busy || !form.username || form.password.length < 12}>Add user</button>
          <p className="auth-hint">{ROLE_HELP[form.role]}. The user must choose their own password at first sign-in.</p>
        </form>
        <div className="rules-section">
          <h3>API tokens</h3>
          <p className="auth-hint">For scripts and integrations. Send as <code>Authorization: Bearer &lt;token&gt;</code>. A token never has more rights than you, and stops working if your account is disabled.</p>
          {newToken && (
            <div className="token-reveal" role="status">
              <p>Copy the token for <strong>{newToken.name}</strong> now. It will not be shown again.</p>
              <code>{newToken.token}</code>
              <div className="users-actions">
                <button className="ghost-button" type="button" onClick={copyToken}>{copied ? 'Copied' : 'Copy'}</button>
                <button className="ghost-button" type="button" onClick={()=>setNewToken(null)}>Done</button>
              </div>
            </div>
          )}
          {tokens.length > 0 && (
            <div className="users-table">
              <div className="users-row users-head">
                <span>Name</span><span>Role</span><span>Status</span><span>Owner</span><span>Expires / last used</span><span />
              </div>
              {tokens.map(t=>(
                <div className="users-row" key={t.id}>
                  <span>{t.name}</span>
                  <span>{t.role}</span>
                  <span>{tokenState(t)}</span>
                  <span>{t.owner}</span>
                  <span>{formatDate(t.expires)}<br /><em>{t.last_used ? `used ${formatDate(t.last_used)}` : 'never used'}</em></span>
                  <span className="users-actions">
                    {!t.revoked && !t.expired && <button className="ghost-button" disabled={busy} onClick={()=>revokeToken(t)}>Revoke</button>}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
        <form className="rules-section users-create" onSubmit={createToken}>
          <h3>New API token</h3>
          <input placeholder="Name, e.g. grafana or backup job" autoComplete="off" value={tokenForm.name} onChange={e=>setTokenForm({ ...tokenForm, name: e.target.value })} />
          <select value={tokenForm.expires_days} onChange={e=>setTokenForm({ ...tokenForm, expires_days: e.target.value })}>
            {[7, 30, 90, 180, 365].map(d=><option key={d} value={d}>Expires in {d} days</option>)}
          </select>
          <select value={tokenForm.role} onChange={e=>setTokenForm({ ...tokenForm, role: e.target.value })}>
            {ROLES.map(r=><option key={r} value={r}>{r}</option>)}
          </select>
          <button className="primary-button" type="submit" disabled={busy || !tokenForm.name.trim()}>Create token</button>
          <p className="auth-hint">{ROLE_HELP[tokenForm.role]}. Give each integration its own token with the lowest role it needs.</p>
        </form>
      </section>
    </div>
  )
}
