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
  const [form, setForm] = useState({ username: '', password: '', role: 'viewer' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async ()=>{
    setUsers(await apiGet('/api/users', []))
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
      </section>
    </div>
  )
}
