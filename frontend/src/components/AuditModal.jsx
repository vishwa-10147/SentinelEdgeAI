import React, { useCallback, useEffect, useState } from 'react'
import { apiGet, errorMessage } from '../api'

const PAGE = 100
const ACTIONS = [
  'login', 'logout', 'password_change', 'mfa_enable', 'mfa_reset',
  'user_create', 'user_update', 'user_delete', 'token_create', 'token_revoke',
  'firewall_block', 'firewall_unblock', 'firewall_policy', 'firewall_rollback', 'firewall_expire',
  'whitelist_add', 'whitelist_remove', 'demo_run', 'demo_presenter'
]

function formatTime(ts){
  return new Date(ts * 1000).toLocaleString()
}

function describe(details){
  if(!details) return ''
  return Object.entries(details).map(([k, v])=>`${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join(', ')
}

export default function AuditModal({ open, onClose }){
  const [entries, setEntries] = useState([])
  const [action, setAction] = useState('')
  const [integrity, setIntegrity] = useState(null)
  const [more, setMore] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const query = (before)=>{
    const params = new URLSearchParams({ limit: String(PAGE) })
    if(action) params.set('action', action)
    if(before) params.set('before', String(before))
    return `/api/audit?${params}`
  }

  const load = useCallback(async ()=>{
    setBusy(true)
    setError('')
    try{
      const [rows, check] = await Promise.all([apiGet(query(), []), apiGet('/api/audit/verify', null)])
      setEntries(rows)
      setMore(rows.length === PAGE)
      setIntegrity(check)
    }catch(e){
      setError(errorMessage(e))
    }finally{
      setBusy(false)
    }
  }, [action])

  useEffect(()=>{ if(open) load() }, [open, load])

  const loadOlder = async ()=>{
    setBusy(true)
    try{
      const rows = await apiGet(query(entries[entries.length - 1].seq), [])
      setEntries([...entries, ...rows])
      setMore(rows.length === PAGE)
    }catch(e){
      setError(errorMessage(e))
    }finally{
      setBusy(false)
    }
  }

  if(!open) return null

  return (
    <div className="modal-backdrop">
      <section className="firewall-modal users-modal" role="dialog" aria-label="Audit log">
        <div className="modal-header">
          <div>
            <h2>Audit log</h2>
            <p>Every sign-in, account change and response action. Entries are hash-chained, so any edit or deletion is detected.</p>
          </div>
          <button className="icon-button" onClick={onClose}>Close</button>
        </div>
        {error && <div className="auth-error users-error" role="alert">{error}</div>}
        {integrity && (
          <div className={integrity.ok ? 'audit-integrity audit-ok' : 'audit-integrity audit-broken'} role="status">
            {integrity.ok
              ? `Chain intact: ${integrity.entries} entries verified.`
              : `Chain broken at entry ${integrity.first_bad_seq}: ${integrity.reason}. The log may have been tampered with.`}
            <code title="Hash of the newest entry; also written to the system journal">{(integrity.head || '').slice(0, 16)}</code>
          </div>
        )}
        <div className="rules-section">
          <div className="audit-toolbar">
            <select value={action} onChange={e=>setAction(e.target.value)} aria-label="Filter by action">
              <option value="">All actions</option>
              {ACTIONS.map(a=><option key={a} value={a}>{a.replace(/_/g, ' ')}</option>)}
            </select>
            <button className="ghost-button" disabled={busy} onClick={load}>Refresh</button>
          </div>
          <div className="users-table">
            <div className="users-row audit-row users-head">
              <span>#</span><span>Time</span><span>Who</span><span>Action</span><span>Target</span><span>Result</span><span>Details</span>
            </div>
            {entries.map(e=>(
              <div className="users-row audit-row" key={e.seq}>
                <span>{e.seq}</span>
                <span>{formatTime(e.ts)}</span>
                <span title={[e.actor_kind, e.role, e.client_ip].filter(Boolean).join(' · ')}>{e.actor}</span>
                <span>{e.action.replace(/_/g, ' ')}</span>
                <span>{e.target || '—'}</span>
                <span className={e.outcome === 'success' ? 'mfa-on' : 'mfa-pending'}>{e.outcome}</span>
                <span className="audit-details">{describe(e.details)}</span>
              </div>
            ))}
            {!busy && entries.length === 0 && <p className="auth-hint">No entries yet.</p>}
          </div>
          {more && <button className="ghost-button" disabled={busy} onClick={loadOlder}>Load older entries</button>}
        </div>
      </section>
    </div>
  )
}
