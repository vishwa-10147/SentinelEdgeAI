import React, { useCallback, useEffect, useState } from 'react'
import { apiGet, apiPost, errorMessage, hasRole } from '../api'

const PRESETS = ['home', 'office', 'ot', 'enterprise']

function ago(ts){
  if(!ts) return 'never'
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts))
  if(s < 120) return `${s} s ago`
  if(s < 7200) return `${Math.round(s / 60)} min ago`
  return `${Math.round(s / 3600)} h ago`
}

function siteHealth(site){
  if(site.revoked) return ['revoked', 'mfa-pending']
  if(!site.last_seen || Date.now() / 1000 - site.last_seen > 900) return ['offline', 'trust-untrusted']
  return ['online', 'mfa-on']
}

export default function FleetModal({ open, onClose, user }){
  const [fleet, setFleet] = useState(null)
  const [site, setSite] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const [form, setForm] = useState({ group: 'default', template: '', target_version: '', preset: 'office', templateName: '' })

  const load = useCallback(async ()=>{
    setBusy(true)
    setError('')
    try{
      const [f, a] = await Promise.all([apiGet('/api/fleet', null), apiGet('/api/fleet/agent', null)])
      setFleet(f)
      setSite(a)
    }catch(e){
      setError(errorMessage(e))
    }finally{
      setBusy(false)
    }
  }, [])

  useEffect(()=>{ if(open) load() }, [open, load])

  const act = async (fn, message)=>{
    setBusy(true)
    setError('')
    setNotice('')
    try{
      const out = await fn()
      setNotice(typeof message === 'function' ? message(out) : message)
      await load()
    }catch(e){
      setError(errorMessage(e))
      setBusy(false)
    }
  }

  const admin = hasRole(user, 'admin')

  if(!open) return null

  return (
    <div className="modal-backdrop">
      <section className="firewall-modal users-modal" role="dialog" aria-label="Fleet">
        <div className="modal-header">
          <div>
            <h2>Fleet</h2>
            <p>Many sites, one console. Sites report every 5 minutes; each group gets a configuration template and a target version that rolls out in stages (canaries first). A failed update pauses the rollout.</p>
          </div>
          <button className="icon-button" onClick={onClose}>Close</button>
        </div>
        {error && <div className="auth-error users-error" role="alert">{error}</div>}
        {notice && <div className="audit-integrity audit-ok" role="status">{notice}</div>}

        {site && (
          <div className="rules-section">
            <h3>This site</h3>
            <div className="audit-integrity" role="status">
              {site.enrolled
                ? `Enrolled as ${site.site_id} in group "${site.state?.group || site.group}" with ${site.fleet_url}. Last report ${ago(site.state?.last_report)}${site.state?.last_error ? ` (last error: ${site.state.last_error})` : ''}. Template: ${site.state?.template?.name || 'none'}. ${site.state?.desired_version ? `Rollout: updating to ${site.state.desired_version}.` : ''}`
                : 'Not enrolled with a fleet server. On the site, run: python -m fleet enroll <url> <code> <fingerprint>'}
            </div>
          </div>
        )}

        {fleet?.server && (
          <>
            <div className="rules-section">
              <h3>Sites</h3>
              <div className="audit-toolbar">
                <button className="ghost-button" disabled={busy} onClick={load}>Refresh</button>
                {admin && (
                  <>
                    <select value={form.group} onChange={e=>setForm({ ...form, group: e.target.value })} aria-label="Group for the new site">
                      {fleet.groups.map(g=><option key={g.name} value={g.name}>{g.name}</option>)}
                    </select>
                    <button className="ghost-button" disabled={busy} onClick={()=>act(()=>apiPost('/api/fleet/codes', { group: form.group }),
                      c=>`Enrolment code ${c.code} (1 hour). On the site: python -m fleet enroll https://<this-device>:9444 ${c.code} ${c.ca_fingerprint}`)}>New enrolment code</button>
                  </>
                )}
              </div>
              <div className="users-table">
                <div className="users-row fleet-row users-head">
                  <span>Site</span><span>Group</span><span>Version</span><span>Status</span><span>Alerts 24 h</span><span>Untrusted</span><span>Restricted</span><span></span>
                </div>
                {fleet.sites.map(s=>{
                  const [label, cls] = siteHealth(s)
                  const r = s.report || {}
                  const restricted = Object.values(r.restrictions || {}).reduce((a, b)=>a + b, 0)
                  return (
                    <div className="users-row fleet-row" key={s.id}>
                      <span title={s.id}>{s.name}</span>
                      <span>{s.grp}</span>
                      <span>{s.version || '—'}</span>
                      <span className={cls}>{label} · {ago(s.last_seen)}</span>
                      <span>{r.alerts_24h ? `${r.alerts_24h.critical} critical, ${r.alerts_24h.high} high` : '—'}</span>
                      <span>{r.trust ? r.trust.untrusted : '—'}</span>
                      <span>{restricted}</span>
                      <span>{admin && !s.revoked && <button className="ghost-button" disabled={busy} onClick={()=>{ if(window.confirm(`Revoke ${s.name}? It can no longer report.`)) act(()=>apiPost(`/api/fleet/sites/${s.id}/revoke`, {}), `${s.name} revoked.`) }}>Revoke</button>}</span>
                    </div>
                  )
                })}
                {fleet.sites.length === 0 && <p className="auth-hint">No sites enrolled yet.</p>}
              </div>
            </div>

            <div className="rules-section">
              <h3>Groups and rollouts</h3>
              <div className="users-table">
                <div className="users-row fleet-group-row users-head"><span>Group</span><span>Template</span><span>Target</span><span>Rollout</span><span></span></div>
                {fleet.groups.map(g=>(
                  <div className="users-row fleet-group-row" key={g.name}>
                    <span>{g.name}</span>
                    <span>{g.template || '—'}</span>
                    <span>{g.target_version || '—'}</span>
                    <span className={g.rollout.paused ? 'trust-untrusted' : ''}>
                      {g.target_version ? `${g.rollout.percent}% released · ${g.rollout.on_target}/${g.rollout.sites} sites on target` : 'no rollout'}
                      {g.rollout.paused && ` · paused: ${g.rollout.paused}`}
                    </span>
                    <span>{admin && g.target_version && (g.rollout.paused
                      ? <button className="ghost-button" disabled={busy} onClick={()=>act(()=>apiPost(`/api/fleet/groups/${g.name}/rollout`, { action: 'resume' }), `${g.name}: rollout resumed.`)}>Resume</button>
                      : <button className="ghost-button" disabled={busy} onClick={()=>act(()=>apiPost(`/api/fleet/groups/${g.name}/rollout`, { action: 'pause' }), `${g.name}: rollout paused.`)}>Pause</button>)}</span>
                  </div>
                ))}
              </div>
              {admin && (
                <form className="audit-toolbar" onSubmit={e=>{ e.preventDefault(); act(()=>apiPost('/api/fleet/groups', { name: form.group, template: form.template || null, target_version: form.target_version || null }), `Group ${form.group} saved.`) }}>
                  <input placeholder="Group" value={form.group} onChange={e=>setForm({ ...form, group: e.target.value })} aria-label="Group name" />
                  <select value={form.template} onChange={e=>setForm({ ...form, template: e.target.value })} aria-label="Template">
                    <option value="">(keep template)</option>
                    {fleet.templates.map(t=><option key={t.name} value={t.name}>{t.name}</option>)}
                  </select>
                  <input placeholder="Target version, e.g. 2.4.0" value={form.target_version} onChange={e=>setForm({ ...form, target_version: e.target.value })} aria-label="Target version" />
                  <button className="ghost-button" disabled={busy || !form.group}>Save group</button>
                </form>
              )}
            </div>

            <div className="rules-section">
              <h3>Federated learning</h3>
              <p className="auth-hint">Sites train the flow autoencoder on their own normal traffic and send back only model updates. The result arrives on every site as a shadow model (scored, never acted on) until you promote it in Operations → Models.</p>
              <div className="users-table">
                <div className="users-row fleet-group-row users-head"><span>Round</span><span>Status</span><span>Updates</span><span>Samples</span><span></span></div>
                {(fleet.federated || []).map(r=>(
                  <div className="users-row fleet-group-row" key={r.id}>
                    <span>#{r.id}</span><span>{r.status}{r.status === 'open' ? ` (needs ${r.min_sites})` : ''}</span><span>{r.updates}</span><span>{r.samples || 0}</span>
                    <span>{admin && r.status === 'open' && <button className="ghost-button" disabled={busy} onClick={()=>act(()=>apiPost('/api/fleet/federated', { close: r.id }), `Round ${r.id} closed.`)}>Close</button>}</span>
                  </div>
                ))}
                {(fleet.federated || []).length === 0 && <p className="auth-hint">No rounds yet.</p>}
              </div>
              {admin && !(fleet.federated || []).some(r=>r.status === 'open') && (
                <div className="audit-toolbar">
                  <button className="ghost-button" disabled={busy} onClick={()=>act(()=>apiPost('/api/fleet/federated', { min_sites: Math.max(1, Math.min(fleet.sites.filter(s=>!s.revoked).length, 3)) }), r=>`Round ${r.id} started; it aggregates when ${r.min_sites} site(s) have answered.`)}>Start a round</button>
                </div>
              )}
            </div>

            <div className="rules-section">
              <h3>Configuration templates</h3>
              <div className="users-table">
                <div className="users-row ot-seg-row users-head"><span>Template</span><span>Version</span><span>Updated</span></div>
                {fleet.templates.map(t=>(
                  <div className="users-row ot-seg-row" key={t.name}><span>{t.name}</span><span><code>{t.version}</code></span><span>{ago(t.updated)} by {t.updated_by}</span></div>
                ))}
                {fleet.templates.length === 0 && <p className="auth-hint">No templates yet. A template is a response policy (YAML) applied to every site in a group.</p>}
              </div>
              {admin && (
                <form className="audit-toolbar" onSubmit={e=>{ e.preventDefault(); act(()=>apiPost('/api/fleet/templates', { name: form.templateName, preset: form.preset }), `Template ${form.templateName} stored.`) }}>
                  <input placeholder="Template name" value={form.templateName} onChange={e=>setForm({ ...form, templateName: e.target.value })} aria-label="Template name" />
                  <select value={form.preset} onChange={e=>setForm({ ...form, preset: e.target.value })} aria-label="Preset">
                    {PRESETS.map(p=><option key={p} value={p}>{p} preset</option>)}
                  </select>
                  <button className="ghost-button" disabled={busy || !form.templateName}>Store template</button>
                </form>
              )}
            </div>
          </>
        )}
        {fleet && !fleet.server && <div className="rules-section"><p className="auth-hint">This device is not a fleet server. To make it one: <code>sudo -u sentinel .venv/bin/python -m fleet init</code> in /opt/sentineledgeai/current.</p></div>}
      </section>
    </div>
  )
}
