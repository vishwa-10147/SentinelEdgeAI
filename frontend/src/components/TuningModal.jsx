import React, { useCallback, useEffect, useState } from 'react'
import { apiDelete, apiGet, apiPost, errorMessage, hasRole } from '../api'

function formatDate(ts){
  return ts ? new Date(ts * 1000).toLocaleDateString() : '—'
}

function scopeText(scope){
  const parts = []
  if(scope.src) parts.push(`from ${scope.src}`)
  if(scope.dst) parts.push(`to ${scope.dst}`)
  if(scope.dport != null) parts.push(`port ${scope.dport}`)
  return parts.join(' ')
}

export default function TuningModal({ open, onClose, user }){
  const [suggestions, setSuggestions] = useState([])
  const [rules, setRules] = useState([])
  const [days, setDays] = useState(30)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async ()=>{
    setBusy(true)
    setError('')
    try{
      const [s, r] = await Promise.all([apiGet('/api/guided-tuning/suggestions', { suggestions: [] }),
                                        apiGet('/api/guided-tuning/rules', { rules: [] })])
      setSuggestions(s.suggestions || [])
      setRules(r.rules || [])
    }catch(e){
      setError(errorMessage(e))
    }finally{
      setBusy(false)
    }
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
      setBusy(false)
    }
  }

  if(!open) return null
  const analyst = hasRole(user, 'analyst')
  const operator = hasRole(user, 'operator')

  return (
    <div className="modal-backdrop">
      <section className="firewall-modal users-modal" role="dialog" aria-label="Tuning">
        <div className="modal-header">
          <div>
            <h2>Tuning</h2>
            <p>Where your false-positive labels concentrate, and a rule for just that place. Rules always expire.</p>
          </div>
          <button className="icon-button" onClick={onClose}>Close</button>
        </div>
        {error && <div className="auth-error users-error" role="alert">{error}</div>}
        <div className="rules-section">
          <h3>Suggestions</h3>
          {analyst && (
            <div className="audit-toolbar">
              <label>Rule lasts{' '}
                <select value={days} onChange={e=>setDays(Number(e.target.value))} aria-label="Rule duration">
                  {[7, 30, 90, 180].map(d=><option key={d} value={d}>{d} days</option>)}
                </select>
              </label>
              <button className="ghost-button" disabled={busy} onClick={load}>Refresh</button>
            </div>
          )}
          {suggestions.map(s=>(
            <div className="tuning-card" key={s.id}>
              <p><strong>{s.text}</strong></p>
              <p className="auth-hint">{s.effect}</p>
              {analyst && (
                <div className="audit-toolbar">
                  <button className="primary-button" disabled={busy} onClick={()=>run(()=>apiPost(`/api/guided-tuning/suggestions/${s.id}/accept`, { action: 'downgrade', days }))}>Downgrade there</button>
                  {s.can_suppress && operator && (
                    <button className="ghost-button" disabled={busy} onClick={()=>{
                      if(window.confirm(`Suppress ${s.kind.replace(/_/g, ' ')} ${scopeText(s.scope)} for ${days} days? Its alerts there will not be shown at all.`)){
                        run(()=>apiPost(`/api/guided-tuning/suggestions/${s.id}/accept`, { action: 'suppress', days }))
                      }
                    }}>Suppress there</button>
                  )}
                  <button className="ghost-button" disabled={busy} onClick={()=>run(()=>apiPost(`/api/guided-tuning/suggestions/${s.id}/dismiss`))}>Not now (30 days)</button>
                </div>
              )}
            </div>
          ))}
          {!busy && suggestions.length === 0 && <p className="auth-hint">No suggestions. They appear when at least 5 alerts of one kind from one place were marked false positive in the last 14 days, and none were confirmed.</p>}
        </div>
        <div className="rules-section">
          <h3>Active rules</h3>
          <div className="users-table">
            <div className="users-row tuning-row users-head">
              <span>Detector</span><span>Where</span><span>Action</span><span>Expires</span><span>By</span><span />
            </div>
            {rules.map(r=>(
              <div className="users-row tuning-row" key={r.id}>
                <span>{r.kind.replace(/_/g, ' ')}</span>
                <span>{scopeText(r.scope)}</span>
                <span>{r.action}</span>
                <span>{formatDate(r.expires)}</span>
                <span title={r.note}>{r.by || '—'}</span>
                <span>{analyst && <button className="ghost-button" disabled={busy} onClick={()=>run(()=>apiDelete(`/api/guided-tuning/rules/${r.id}`))}>Remove</button>}</span>
              </div>
            ))}
            {!busy && rules.length === 0 && <p className="auth-hint">No rules: every detector runs at full strength everywhere.</p>}
          </div>
        </div>
      </section>
    </div>
  )
}
