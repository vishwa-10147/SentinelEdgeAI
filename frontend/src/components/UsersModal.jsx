import React, { useCallback, useEffect, useState } from 'react'
import { apiDelete, apiGet, apiPatch, apiPost, apiPut, errorMessage } from '../api'

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
                  <span>{u.username}{self && <em> (you)</em>}{u.auth_source && u.auth_source !== 'local' && <em className="sso-tag" title={u.auth_source === 'ldap' ? 'Signs in with the directory (LDAP/AD) password; the role follows the directory groups' : 'Signs in through single sign-on; the role follows the identity provider groups'}> {u.auth_source === 'ldap' ? 'LDAP' : u.auth_source === 'saml' ? 'SAML' : 'SSO'}</em>}</span>
                  <span>
                    <select value={u.role} disabled={busy || self || (u.auth_source && u.auth_source !== 'local')} onChange={e=>run(()=>apiPatch(`/api/users/${encodeURIComponent(u.username)}`, { role: e.target.value }))}>
                      {ROLES.map(r=><option key={r} value={r}>{r}</option>)}
                    </select>
                  </span>
                  <span>{u.disabled ? 'Disabled' : u.locked ? 'Locked' : u.must_change_password ? 'Must change password' : 'Active'}</span>
                  <span className={u.mfa_enabled ? 'mfa-on' : u.mfa_setup_required ? 'mfa-pending' : 'mfa-off'}>
                    {u.mfa_enabled ? 'On' : u.mfa_setup_required ? 'Setup pending' : 'Off'}
                  </span>
                  <span>{formatDate(u.last_login)}</span>
                  <span className="users-actions">
                    {(!u.auth_source || u.auth_source === 'local') && <button className="ghost-button" disabled={busy} onClick={()=>resetPassword(u.username)}>Reset password</button>}
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
        <SsoSettings />
        <SamlSettings />
        <LdapSettings />
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


function parseGroupRoles(text){
  const out = {}
  for(const line of text.split('\n')){
    const [group, role] = line.split('=').map(x=>x && x.trim())
    if(group && role) out[group] = role
  }
  return out
}

function SsoSettings(){
  const [cfg, setCfg] = useState(null)
  const [groups, setGroups] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(()=>{
    apiGet('/api/sso', null).then(c=>{
      setCfg(c)
      setGroups(Object.entries(c?.group_roles || {}).map(([g, r])=>`${g} = ${r}`).join('\n'))
    }).catch(()=>{})
  }, [])

  if(!cfg) return null
  const set = (k, v)=>setCfg({ ...cfg, [k]: v })
  const save = async (e)=>{
    e.preventDefault()
    setBusy(true)
    setMessage('')
    try{
      const saved = await apiPut('/api/sso', { ...cfg, group_roles: parseGroupRoles(groups), default_role: cfg.default_role || null })
      setCfg(saved)
      setMessage('Saved.')
    }catch(err){
      setMessage(errorMessage(err))
    }finally{
      setBusy(false)
    }
  }
  return (
    <form className="rules-section users-create sso-settings" onSubmit={save}>
      <h3>Single sign-on (OpenID Connect)</h3>
      <label><input type="checkbox" checked={!!cfg.enabled} onChange={e=>set('enabled', e.target.checked)} /> Enabled</label>
      <input placeholder="Button label, e.g. Sign in with Microsoft" value={cfg.label || ''} onChange={e=>set('label', e.target.value)} aria-label="Button label" />
      <input placeholder="Issuer, e.g. https://login.microsoftonline.com/<tenant>/v2.0" value={cfg.issuer || ''} onChange={e=>set('issuer', e.target.value)} aria-label="Issuer" />
      <input placeholder="Client id" value={cfg.client_id || ''} onChange={e=>set('client_id', e.target.value)} aria-label="Client id" />
      <input placeholder="Client secret" type="password" autoComplete="off" value={cfg.client_secret || ''} onChange={e=>set('client_secret', e.target.value)} aria-label="Client secret" />
      <input placeholder="Redirect URI (default: this console + /api/auth/oidc/callback)" value={cfg.redirect_uri || ''} onChange={e=>set('redirect_uri', e.target.value)} aria-label="Redirect URI" />
      <textarea rows={4} placeholder={'One per line: group = role\nSecOps = operator\nIT-Admins = admin'} value={groups} onChange={e=>setGroups(e.target.value)} aria-label="Group to role mapping" />
      <select value={cfg.default_role || ''} onChange={e=>set('default_role', e.target.value)} aria-label="Default role">
        <option value="">Users in no mapped group: refused</option>
        {ROLES.map(r=><option key={r} value={r}>Users in no mapped group: {r}</option>)}
      </select>
      <label><input type="checkbox" checked={!!cfg.trust_idp_mfa} onChange={e=>set('trust_idp_mfa', e.target.checked)} /> The identity provider always enforces MFA (otherwise Operator and Admin need MFA in the token's amr claim)</label>
      <button className="primary-button" type="submit" disabled={busy}>Save SSO settings</button>
      {message && <p className="auth-hint" role="status">{message}</p>}
    </form>
  )
}


function useConfig(path){
  const [cfg, setCfg] = useState(null)
  const [groups, setGroups] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(()=>{
    apiGet(path, null).then(c=>{
      setCfg(c)
      setGroups(Object.entries(c?.group_roles || {}).map(([g, r])=>`${g} = ${r}`).join('\n'))
    }).catch(()=>{})
  }, [path])
  const save = async (e, extra = {})=>{
    e.preventDefault()
    setBusy(true)
    setMessage('')
    try{
      const saved = await apiPut(path, { ...cfg, ...extra, group_roles: parseGroupRoles(groups), default_role: cfg.default_role || null })
      setCfg(saved)
      setMessage('Saved.')
    }catch(err){
      setMessage(errorMessage(err))
    }finally{
      setBusy(false)
    }
  }
  return { cfg, setCfg, groups, setGroups, message, setMessage, busy, setBusy, save }
}

function RoleMapping({ groups, setGroups, cfg, set }){
  return (
    <>
      <textarea rows={4} placeholder={'One per line: group = role\nSecOps = operator\nIT-Admins = admin'} value={groups} onChange={e=>setGroups(e.target.value)} aria-label="Group to role mapping" />
      <select value={cfg.default_role || ''} onChange={e=>set('default_role', e.target.value)} aria-label="Default role">
        <option value="">Users in no mapped group: refused</option>
        {ROLES.map(r=><option key={r} value={r}>Users in no mapped group: {r}</option>)}
      </select>
    </>
  )
}

function SamlSettings(){
  const c = useConfig('/api/saml')
  const [certs, setCerts] = useState(null)
  if(!c.cfg) return null
  const set = (k, v)=>c.setCfg({ ...c.cfg, [k]: v })
  const certText = certs ?? (c.cfg.idp_certs || []).join('\n')
  return (
    <form className="rules-section users-create sso-settings" onSubmit={e=>c.save(e, { idp_certs: certText })}>
      <h3>Single sign-on (SAML 2.0)</h3>
      <p className="auth-hint">Give the identity provider this console's metadata: <a href="/api/auth/saml/metadata" target="_blank" rel="noreferrer">/api/auth/saml/metadata</a>. Assertions must be signed (SHA-256); encrypted assertions are not supported.</p>
      <label><input type="checkbox" checked={!!c.cfg.enabled} onChange={e=>set('enabled', e.target.checked)} /> Enabled</label>
      <input placeholder="Button label, e.g. Sign in with ADFS" value={c.cfg.label || ''} onChange={e=>set('label', e.target.value)} aria-label="SAML button label" />
      <input placeholder="IdP entity id (Issuer)" value={c.cfg.idp_entity_id || ''} onChange={e=>set('idp_entity_id', e.target.value)} aria-label="IdP entity id" />
      <input placeholder="IdP single sign-on URL (HTTP-Redirect), https://..." value={c.cfg.idp_sso_url || ''} onChange={e=>set('idp_sso_url', e.target.value)} aria-label="IdP SSO URL" />
      <textarea rows={4} placeholder="IdP signing certificate(s), PEM (-----BEGIN CERTIFICATE-----)" value={certText} onChange={e=>setCerts(e.target.value)} aria-label="IdP certificates" />
      <input placeholder="Groups attribute (default: groups; Entra: http://schemas.microsoft.com/ws/2008/06/identity/claims/groups)" value={c.cfg.groups_attribute || ''} onChange={e=>set('groups_attribute', e.target.value)} aria-label="Groups attribute" />
      <input placeholder="Username attribute (default: the NameID)" value={c.cfg.username_attribute || ''} onChange={e=>set('username_attribute', e.target.value)} aria-label="Username attribute" />
      <RoleMapping groups={c.groups} setGroups={c.setGroups} cfg={c.cfg} set={set} />
      <label><input type="checkbox" checked={!!c.cfg.trust_idp_mfa} onChange={e=>set('trust_idp_mfa', e.target.checked)} /> The identity provider always enforces MFA (otherwise Operator and Admin need an MFA authentication context)</label>
      <button className="primary-button" type="submit" disabled={c.busy}>Save SAML settings</button>
      {c.message && <p className="auth-hint" role="status">{c.message}</p>}
    </form>
  )
}

function LdapSettings(){
  const c = useConfig('/api/ldap')
  const [probe, setProbe] = useState('')
  const [result, setResult] = useState(null)
  if(!c.cfg) return null
  const set = (k, v)=>c.setCfg({ ...c.cfg, [k]: v })
  const test = async ()=>{
    setResult(null)
    try{ setResult(await apiPost('/api/ldap/test', { username: probe })) }catch(err){ setResult({ ok: false, error: errorMessage(err) }) }
  }
  return (
    <form className="rules-section users-create sso-settings" onSubmit={c.save}>
      <h3>Directory sign-in (LDAP / Active Directory)</h3>
      <p className="auth-hint">Usernames that are not local accounts are checked against the directory on the normal sign-in form. Operators and Admins still enrol an authenticator app on this console. Only ldaps:// or StartTLS; the server certificate is verified.</p>
      <label><input type="checkbox" checked={!!c.cfg.enabled} onChange={e=>set('enabled', e.target.checked)} /> Enabled</label>
      <input placeholder="URL, e.g. ldaps://dc1.corp.example" value={c.cfg.url || ''} onChange={e=>set('url', e.target.value)} aria-label="Directory URL" />
      <label><input type="checkbox" checked={!!c.cfg.start_tls} onChange={e=>set('start_tls', e.target.checked)} /> Use StartTLS (for ldap:// URLs)</label>
      <input placeholder="CA certificate file on the appliance (optional; default: system CAs)" value={c.cfg.ca_file || ''} onChange={e=>set('ca_file', e.target.value)} aria-label="CA file" />
      <input placeholder="Base DN, e.g. DC=corp,DC=example" value={c.cfg.base_dn || ''} onChange={e=>set('base_dn', e.target.value)} aria-label="Base DN" />
      <input placeholder="Service account DN (to find users and groups)" value={c.cfg.bind_dn || ''} onChange={e=>set('bind_dn', e.target.value)} aria-label="Service account DN" />
      <input placeholder="Service account password" type="password" autoComplete="off" value={c.cfg.bind_password || ''} onChange={e=>set('bind_password', e.target.value)} aria-label="Service account password" />
      <input placeholder="Or, without a service account: user DN template, e.g. {username}@corp.example" value={c.cfg.user_dn_template || ''} onChange={e=>set('user_dn_template', e.target.value)} aria-label="User DN template" />
      <input placeholder="User filter" value={c.cfg.user_filter || ''} onChange={e=>set('user_filter', e.target.value)} aria-label="User filter" />
      <RoleMapping groups={c.groups} setGroups={c.setGroups} cfg={c.cfg} set={set} />
      <label><input type="checkbox" checked={!!c.cfg.nested_groups} onChange={e=>set('nested_groups', e.target.checked)} /> Follow nested groups (Active Directory)</label>
      <button className="primary-button" type="submit" disabled={c.busy}>Save directory settings</button>
      <div className="audit-toolbar">
        <input placeholder="Test: look up a username" value={probe} onChange={e=>setProbe(e.target.value)} aria-label="Username to look up" />
        <button className="ghost-button" type="button" disabled={!probe} onClick={test}>Look up</button>
      </div>
      {result && <p className="auth-hint" role="status">{result.ok ? `${result.dn}: role ${result.role || 'none (refused)'}; groups ${(result.groups || []).join('; ') || 'none'}` : result.error}</p>}
      {c.message && <p className="auth-hint" role="status">{c.message}</p>}
    </form>
  )
}
