import React, { useCallback, useEffect, useState } from 'react'
import { apiGet, apiPost, errorMessage, hasRole } from '../api'

function formatTime(ts){
  return ts ? new Date(ts * 1000).toLocaleString() : '—'
}

const SEVERITY_CLASS = { critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low' }
const FILTERS = ['open', 'acknowledged', 'resolved', 'all']

function AssistantBox({ incidentId }){
  const [status, setStatus] = useState(null)
  const [question, setQuestion] = useState('')
  const [reply, setReply] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(()=>{ apiGet('/api/assistant', null).then(setStatus).catch(()=>setStatus(null)) }, [])
  useEffect(()=>{ setReply(null); setError('') }, [incidentId])
  if(!status?.enabled) return null
  const ask = async (q)=>{
    setBusy(true)
    setError('')
    try{
      setReply(await apiPost('/api/assistant/ask', { incident_id: incidentId, question: q }))
    }catch(e){
      setError(errorMessage(e))
    }finally{
      setBusy(false)
    }
  }
  return (
    <div className="assistant-box">
      <h3>Ask the assistant</h3>
      <div className="audit-toolbar">
        <button className="ghost-button" disabled={busy} onClick={()=>ask('Explain what happened in plain language and what I should do first.')}>Explain this incident</button>
      </div>
      <form className="audit-toolbar" onSubmit={e=>{ e.preventDefault(); if(question.trim()) ask(question.trim()) }}>
        <input placeholder="Ask about this incident" maxLength={500} value={question} onChange={e=>setQuestion(e.target.value)} aria-label="Question for the assistant" />
        <button className="ghost-button" disabled={busy || !question.trim()}>{busy ? 'Thinking…' : 'Ask'}</button>
      </form>
      {error && <div className="auth-error" role="alert">{error}</div>}
      {reply && (
        <div className="assistant-reply" role="status">
          <p className="assistant-text">{reply.answer}</p>
          <p className="auth-hint">{reply.disclaimer} ({reply.backend}{reply.model ? ` · ${reply.model}` : ''}, {reply.seconds}s). It cannot take actions; every action goes through the console.</p>
        </div>
      )}
    </div>
  )
}

function TimelineEntry({ e }){
  if(e.type === 'response'){
    return (
      <li className="incident-event incident-response">
        <span className="incident-time">{formatTime(e.ts)}</span>
        <span><strong>{e.action}</strong> {e.ip}{e.ttl ? ` for ${Math.round(e.ttl / 60)} min` : ''}{e.dry_run ? ' (dry run)' : ''}{e.reason ? `: ${e.reason}` : ''}</span>
      </li>
    )
  }
  return (
    <li className="incident-event">
      <span className="incident-time">{formatTime(e.ts)}</span>
      <span>
        <strong>{e.kind.replace(/_/g, ' ')}</strong> {e.src}{e.dst ? ` → ${e.dst}` : ''} · risk {Math.round(e.risk)}{e.technique ? ` · ${e.technique}` : ''}
        {e.evidence?.length > 0 && <span className="audit-details"> {e.evidence.join(' · ')}</span>}
      </span>
    </li>
  )
}

export default function IncidentsModal({ open, onClose, user }){
  const [filter, setFilter] = useState('open')
  const [items, setItems] = useState([])
  const [counts, setCounts] = useState({})
  const [selected, setSelected] = useState(null)
  const [note, setNote] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async ()=>{
    setBusy(true)
    setError('')
    try{
      const body = await apiGet(filter === 'all' ? '/api/incidents' : `/api/incidents?status=${filter}`, { incidents: [], counts: {} })
      setItems(body.incidents || [])
      setCounts(body.counts || {})
    }catch(e){
      setError(errorMessage(e))
    }finally{
      setBusy(false)
    }
  }, [filter])

  useEffect(()=>{ if(open) load() }, [open, load])

  const openIncident = async (id)=>{
    setBusy(true)
    setError('')
    try{
      setSelected(await apiGet(`/api/incidents/${id}`, null))
      setNote('')
    }catch(e){
      setError(errorMessage(e))
    }finally{
      setBusy(false)
    }
  }

  const setStatus = async (status)=>{
    setBusy(true)
    setError('')
    try{
      await apiPost(`/api/incidents/${selected.id}/status`, { status, note })
      await openIncident(selected.id)
      await load()
    }catch(e){
      setError(errorMessage(e))
    }finally{
      setBusy(false)
    }
  }

  if(!open) return null
  const analyst = hasRole(user, 'analyst')

  return (
    <div className="modal-backdrop">
      <section className="firewall-modal users-modal" role="dialog" aria-label="Incidents">
        <div className="modal-header">
          <div>
            <h2>Incidents</h2>
            <p>Related alerts, devices and responses grouped into one story, with what to do now.</p>
          </div>
          <button className="icon-button" onClick={onClose}>Close</button>
        </div>
        {error && <div className="auth-error users-error" role="alert">{error}</div>}
        {!selected && (
          <div className="rules-section">
            <div className="audit-toolbar">
              {FILTERS.map(f=>(
                <button key={f} className={f === filter ? 'primary-button' : 'ghost-button'} onClick={()=>setFilter(f)}>
                  {f}{f !== 'all' && counts[f] != null ? ` (${counts[f]})` : ''}
                </button>
              ))}
              <button className="ghost-button" disabled={busy} onClick={load}>Refresh</button>
            </div>
            <div className="users-table">
              <div className="users-row incident-row users-head">
                <span>Severity</span><span>Incident</span><span>Alerts</span><span>Last activity</span><span>Status</span>
              </div>
              {items.map(i=>(
                <button className="users-row incident-row incident-link" key={i.id} onClick={()=>openIncident(i.id)}>
                  <span className={SEVERITY_CLASS[i.severity]}>{i.severity}</span>
                  <span>{i.title}</span>
                  <span>{i.alert_count}{i.responses ? ` · ${i.responses} response${i.responses > 1 ? 's' : ''}` : ''}</span>
                  <span>{formatTime(i.last_seen)}</span>
                  <span>{i.status}</span>
                </button>
              ))}
              {!busy && items.length === 0 && <p className="auth-hint">No {filter === 'all' ? '' : filter} incidents.</p>}
            </div>
          </div>
        )}
        {selected && (
          <div className="rules-section">
            <div className="audit-toolbar">
              <button className="ghost-button" onClick={()=>setSelected(null)}>← All incidents</button>
            </div>
            <h3><span className={SEVERITY_CLASS[selected.severity]}>{selected.severity}</span> {selected.title}</h3>
            <p className="auth-hint">
              {formatTime(selected.first_seen)} – {formatTime(selected.last_seen)} · {selected.alert_count} alerts ·
              sources {selected.sources.join(', ')}{selected.targets.length ? ` · targets ${selected.targets.join(', ')}` : ''}
              {selected.techniques.length ? ` · ${selected.techniques.join(', ')}` : ''} · status <strong>{selected.status}</strong>
              {selected.note ? ` (“${selected.note}” — ${selected.updated_by || 'unknown'})` : ''}
            </p>
            {selected.tickets?.length > 0 && (
              <p className="auth-hint">Tickets: {selected.tickets.map((t, n)=>(
                <span key={t.target}>{n ? ' · ' : ''}{t.url && /^https:\/\//.test(t.url)
                  ? <a href={t.url} target="_blank" rel="noopener noreferrer">{t.key || t.target}</a>
                  : (t.key || t.target)} ({t.target}{t.resolved ? ', resolved' : ''})</span>
              ))}</p>
            )}
            <h3>What to do now</h3>
            <ol className="incident-checklist">
              {selected.checklist.map((s, n)=><li key={n}>{s}</li>)}
            </ol>
            {analyst && (
              <form className="audit-toolbar" onSubmit={e=>e.preventDefault()}>
                <input placeholder="Note: what you found or did" value={note} onChange={e=>setNote(e.target.value)} aria-label="Note" />
                {selected.status !== 'acknowledged' && <button className="ghost-button" disabled={busy} onClick={()=>setStatus('acknowledged')}>Acknowledge</button>}
                {selected.status !== 'resolved' && <button className="primary-button" disabled={busy} onClick={()=>setStatus('resolved')}>Resolve</button>}
                {selected.status !== 'open' && <button className="ghost-button" disabled={busy} onClick={()=>setStatus('open')}>Reopen</button>}
              </form>
            )}
            <AssistantBox incidentId={selected.id} />
            <h3>Timeline</h3>
            <ul className="incident-timeline">
              {selected.timeline.map((e, n)=><TimelineEntry key={n} e={e} />)}
            </ul>
          </div>
        )}
      </section>
    </div>
  )
}
