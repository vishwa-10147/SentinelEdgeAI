import React, { useCallback, useEffect, useState } from 'react'
import { API_BASE, apiGet, apiPost, errorMessage, getAccessToken, hasRole } from '../api'

const TABS = [['response', 'Response'], ['policy', 'Policy'], ['sensors', 'Sensors'], ['models', 'Models & evaluation'], ['compliance', 'Compliance']]

function when(ts){
  return ts ? new Date(ts * 1000).toLocaleString() : '—'
}

function pct(x){
  return x == null ? '—' : `${(x * 100).toFixed(1)}%`
}

function ResponseTab({ user, act, busy, reloadKey }){
  const [restrictions, setRestrictions] = useState([])
  const [pending, setPending] = useState([])
  const [tuning, setTuning] = useState(null)
  useEffect(()=>{
    Promise.all([apiGet('/api/firewall/restrictions', []), apiGet('/api/playbook/pending', []), apiGet('/api/tuning', null)])
      .then(([r, p, t])=>{ setRestrictions(r || []); setPending(p || []); setTuning(t) }).catch(()=>{})
  }, [reloadKey])
  const operator = hasRole(user, 'operator')
  const admin = hasRole(user, 'admin')
  return (
    <>
      {tuning && (
        <div className="rules-section">
          <h3>Response tuning</h3>
          <p className="auth-hint">Learns which response resolves each kind of incident with the least disruption: never stronger than the playbook, never gentler than "{tuning.config.min_action}", always stronger after a failed response. In <b>recommend</b> mode it only shows and audits what it would do.</p>
          {admin && (
            <div className="audit-toolbar">
              {['off', 'recommend', 'apply'].map(m=>(
                <button key={m} className={m === tuning.config.mode ? 'primary-button' : 'ghost-button'} disabled={busy || m === tuning.config.mode}
                  onClick={()=>{ if(m !== 'apply' || window.confirm('Let response tuning choose gentler responses within the playbook\'s bounds?')) act(()=>apiPost('/api/tuning', { mode: m }), `Response tuning: ${m}.`) }}>{m}</button>
              ))}
            </div>
          )}
          <div className="users-table">
            <div className="users-row ot-seg-row users-head"><span>Kind</span><span>Evidence (resolved / not)</span><span>Instead of block</span></div>
            {tuning.kinds.map(k=>(
              <div className="users-row ot-seg-row" key={k.kind}>
                <span>{k.kind}</span>
                <span className="audit-details">{Object.entries(k.evidence).map(([a, e])=>`${a} ${e.resolved}/${e.not_resolved}`).join(', ')}</span>
                <span>{k.recommended_instead_of_block}</span>
              </div>
            ))}
            {tuning.kinds.length === 0 && <p className="auth-hint">No settled responses yet; outcomes are judged one hour after each response.</p>}
          </div>
        </div>
      )}
      <div className="rules-section">
        <h3>Waiting for approval</h3>
        <p className="auth-hint">Playbook actions above the approval threshold wait here for an Operator.</p>
        <div className="users-table">
          <div className="users-row ops-pending-row users-head"><span>Device</span><span>Action</span><span>Risk</span><span>Reason</span><span>Since</span><span></span></div>
          {pending.map(p=>(
            <div className="users-row ops-pending-row" key={p.id}>
              <span>{p.ip}</span><span>{p.action}{p.ttl ? ` (${Math.round(p.ttl / 60)} min)` : ''}</span><span>{p.risk}</span>
              <span className="audit-details">{p.reason}</span><span>{when(p.created)}</span>
              <span>{operator && <>
                <button className="ghost-button" disabled={busy} onClick={()=>act(()=>apiPost(`/api/playbook/pending/${p.id}/approve`, {}), `${p.action} on ${p.ip} approved.`)}>Approve</button>
                <button className="ghost-button" disabled={busy} onClick={()=>act(()=>apiPost(`/api/playbook/pending/${p.id}/deny`, {}), `${p.action} on ${p.ip} denied.`)}>Deny</button>
              </>}</span>
            </div>
          ))}
          {pending.length === 0 && <p className="auth-hint">Nothing waiting.</p>}
        </div>
      </div>
      <div className="rules-section">
        <h3>Active restrictions</h3>
        <div className="users-table">
          <div className="users-row ops-restrict-row users-head"><span>Device</span><span>Kind</span><span>Reason</span><span>Expires</span><span></span></div>
          {restrictions.map(r=>(
            <div className="users-row ops-restrict-row" key={`${r.kind}-${r.ip}`}>
              <span>{r.ip}</span><span>{r.kind}{r.dry_run ? ' (dry run)' : ''}</span><span className="audit-details">{r.reason || '—'}</span>
              <span>{r.expires ? when(r.expires) : 'never'}</span>
              <span>{operator && <button className="ghost-button" disabled={busy} onClick={()=>act(()=>apiPost('/api/firewall/release', { kind: r.kind, ip: r.ip }), `${r.ip} released.`)}>Release</button>}</span>
            </div>
          ))}
          {restrictions.length === 0 && <p className="auth-hint">No quarantine, rate limit or containment in force.</p>}
        </div>
      </div>
    </>
  )
}

function PolicyTab({ user, act, busy, reloadKey }){
  const [yaml, setYaml] = useState('')
  const [preview, setPreview] = useState(null)
  useEffect(()=>{ apiGet('/api/policy', null).then(p=>{ if(p) setYaml(p.yaml); setPreview(null) }).catch(()=>{}) }, [reloadKey])
  const admin = hasRole(user, 'admin')
  return (
    <div className="rules-section">
      <h3>Response policy</h3>
      <p className="auth-hint">Response mode, TTLs, whitelist, management hosts and the playbook, as YAML. Check a change first; nothing is applied until you confirm.</p>
      <textarea className="ops-yaml" value={yaml} onChange={e=>{ setYaml(e.target.value); setPreview(null) }} readOnly={!admin} spellCheck={false} aria-label="Response policy YAML" />
      {admin && (
        <div className="audit-toolbar">
          <button className="ghost-button" disabled={busy} onClick={async ()=>{ try{ setPreview(await apiPost('/api/policy/diff', { yaml })) }catch(e){ setPreview({ valid: false, errors: [errorMessage(e)], warnings: [], changes: [] }) } }}>Check changes</button>
          <button className="primary-button" disabled={busy || !preview?.valid || !preview.changes.length} onClick={()=>act(()=>apiPost('/api/policy/apply', { yaml }), out=>`Policy applied: ${out.changes.length} change(s).`)}>Apply</button>
        </div>
      )}
      {preview && (
        <div className={preview.valid ? 'audit-integrity' : 'audit-integrity audit-broken'} role="status">
          {preview.errors.map(e=><div key={e}>Error: {e}</div>)}
          {preview.warnings.map(w=><div key={w}>Warning: {w}</div>)}
          {preview.valid && !preview.changes.length && <div>No changes.</div>}
          {preview.changes.map(c=><div key={c.key}><code>{c.key}</code>: {JSON.stringify(c.old)} → {JSON.stringify(c.new)}</div>)}
        </div>
      )}
    </div>
  )
}

function SensorsTab({ user, act, busy, reloadKey }){
  const [sensors, setSensors] = useState(null)
  const [own, setOwn] = useState(null)
  useEffect(()=>{
    apiGet('/api/brain/sensors', null).then(setSensors).catch(()=>setSensors(null))
    apiGet('/api/sensor/status', null).then(setOwn).catch(()=>setOwn(null))
  }, [reloadKey])
  const admin = hasRole(user, 'admin')
  return (
    <>
      {own && (
        <div className="rules-section">
          <h3>This device as a sensor</h3>
          <div className="audit-integrity" role="status">
            {own.enrolled ? `Enrolled as ${own.enrolled.sensor_id} with ${own.enrolled.brain_url}. ${own.buffered} flows buffered, ${own.dropped} dropped.` : 'Not enrolled with a brain (Standalone or Brain role).'}
          </div>
        </div>
      )}
      <div className="rules-section">
        <h3>Sensors of this brain</h3>
        {admin && <div className="audit-toolbar"><button className="ghost-button" disabled={busy} onClick={()=>act(()=>apiPost('/api/brain/codes', {}), out=>`Enrolment code ${out.code}. On the sensor: ${out.command || ''}`)}>New enrolment code</button></div>}
        <div className="users-table">
          <div className="users-row ops-sensor-row users-head"><span>Sensor</span><span>Name</span><span>Last seen</span><span>Flows</span><span>Health</span><span></span></div>
          {(sensors || []).map(s=>(
            <div className="users-row ops-sensor-row" key={s.id}>
              <span>{s.id}</span><span>{s.name}</span><span>{when(s.last_seen)}</span><span>{s.flows}</span>
              <span className="audit-details">{s.revoked ? 'revoked' : s.health ? Object.entries(s.health).slice(0, 4).map(([k, v])=>`${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join(', ') : '—'}</span>
              <span>{admin && !s.revoked && <button className="ghost-button" disabled={busy} onClick={()=>{ if(window.confirm(`Revoke ${s.id}? It can no longer send flows or receive commands.`)) act(()=>apiPost(`/api/brain/sensors/${s.id}/revoke`, {}), `${s.id} revoked.`) }}>Revoke</button>}</span>
            </div>
          ))}
          {(!sensors || sensors.length === 0) && <p className="auth-hint">No sensors. Choose the Brain role in Setup, then create an enrolment code.</p>}
        </div>
      </div>
    </>
  )
}

function ModelsTab({ user, act, busy, reloadKey }){
  const [models, setModels] = useState({})
  const [feedback, setFeedback] = useState([])
  const [evaluation, setEvaluation] = useState(null)
  useEffect(()=>{
    apiGet('/api/models', {}).then(m=>setModels(m || {})).catch(()=>{})
    apiGet('/api/alerts/feedback', []).then(f=>setFeedback(f || [])).catch(()=>{})
    apiGet('/api/eval/latest', null).then(setEvaluation).catch(()=>setEvaluation(null))
  }, [reloadKey])
  const admin = hasRole(user, 'admin')
  return (
    <>
      <div className="rules-section">
        <h3>Model registry</h3>
        <p className="auth-hint">Signed models move shadow → canary → active; a tampered model is refused.</p>
        <div className="users-table">
          <div className="users-row ops-model-row users-head"><span>Model</span><span>Version</span><span>Stage</span><span>Created</span><span></span></div>
          {Object.entries(models).flatMap(([name, entry])=>Object.entries(entry.versions || {}).map(([v, info])=>(
            <div className="users-row ops-model-row" key={`${name}-${v}`}>
              <span>{name}</span><span>v{v}</span><span>{info.stage}{info.stage === 'canary' ? ` (${entry.canary_percent}%)` : ''}</span><span>{when(info.created)}</span>
              <span>{admin && <>
                {info.stage !== 'active' && info.stage !== 'retired' && <button className="ghost-button" disabled={busy} onClick={()=>act(()=>apiPost(`/api/models/${name}/${v}/stage`, { stage: info.stage === 'shadow' ? 'canary' : 'active' }), `${name} v${v} promoted.`)}>{info.stage === 'shadow' ? 'To canary' : 'Activate'}</button>}
                {info.stage === 'active' && entry.previous_active && <button className="ghost-button" disabled={busy} onClick={()=>act(()=>apiPost(`/api/models/${name}/rollback`, {}), `${name} rolled back.`)}>Roll back</button>}
              </>}</span>
            </div>
          )))}
          {Object.keys(models).length === 0 && <p className="auth-hint">No registered models.</p>}
        </div>
      </div>
      <div className="rules-section">
        <h3>Analyst feedback</h3>
        <div className="users-table">
          <div className="users-row ot-seg-row users-head"><span>Detector</span><span>True / false positives</span><span>Precision</span></div>
          {feedback.map(f=>(
            <div className="users-row ot-seg-row" key={f.kind}><span>{f.kind}</span><span>{f.true_positives} / {f.false_positives}</span><span>{pct(f.precision)}</span></div>
          ))}
          {feedback.length === 0 && <p className="auth-hint">No alerts labelled yet. Labels recalibrate each detector and feed the trust scores.</p>}
        </div>
      </div>
      <div className="rules-section">
        <h3>Latest evaluation</h3>
        {evaluation ? (
          <>
            <div className="audit-integrity" role="status">
              {evaluation.dataset}: {pct(evaluation.detection_rate)} of {evaluation.attack_instances} attacks detected, {pct(evaluation.false_positive_rate)} false positives over {evaluation.benign_sources} benign sources ({evaluation.events} events).
            </div>
            <div className="users-table">
              <div className="users-row ot-seg-row users-head"><span>Attack</span><span>Detected</span><span>Median delay</span></div>
              {Object.entries(evaluation.classes || {}).map(([k, c])=>(
                <div className="users-row ot-seg-row" key={k}><span>{k}</span><span>{c.detected}/{c.instances}</span><span>{c.median_delay_s == null ? '—' : `${c.median_delay_s} s`}</span></div>
              ))}
            </div>
          </>
        ) : <p className="auth-hint">No evaluation yet. Run <code>python -m evaluation.harness</code>.</p>}
      </div>
    </>
  )
}

const STATUS_CLASS = { met: 'mfa-on', partial: 'mfa-pending', gap: 'trust-untrusted', manual: '', 'n/a': '' }

function ComplianceTab({ user, reloadKey }){
  const [overview, setOverview] = useState(null)
  const [pack, setPack] = useState('iso27001')
  const [report, setReport] = useState(null)
  const [error, setError] = useState('')
  const admin = hasRole(user, 'admin')
  useEffect(()=>{
    if(!admin) return
    apiGet('/api/compliance', null).then(setOverview).catch(e=>setError(errorMessage(e)))
  }, [reloadKey, admin])
  useEffect(()=>{
    if(!admin) return
    setReport(null)
    apiGet(`/api/compliance/${pack}`, null).then(setReport).catch(e=>setError(errorMessage(e)))
  }, [pack, reloadKey, admin])
  if(!admin) return <div className="rules-section"><p className="auth-hint">Compliance evidence is available to Admins.</p></div>
  const download = async ()=>{
    try{
      const res = await fetch(`${API_BASE}/api/compliance/${pack}/pdf`, { headers: { Authorization: `Bearer ${getAccessToken()}` } })
      if(!res.ok) throw new Error(`HTTP ${res.status}`)
      const url = URL.createObjectURL(await res.blob())
      const a = document.createElement('a')
      a.href = url
      a.download = `sentineledgeai-${pack}-evidence.pdf`
      a.click()
      URL.revokeObjectURL(url)
    }catch(e){ setError(errorMessage(e)) }
  }
  return (
    <div className="rules-section">
      <h3>Compliance evidence</h3>
      <p className="auth-hint">What this appliance can show for each control, read live. Documentation support, not a certification; organisational controls are marked manual.</p>
      {error && <div className="auth-error users-error" role="alert">{error}</div>}
      <div className="audit-toolbar" role="tablist">
        {overview && Object.entries(overview).map(([k, o])=>(
          <button key={k} className={k === pack ? 'primary-button' : 'ghost-button'} onClick={()=>setPack(k)} title={o.title}>
            {k} · {o.totals.met} met, {o.totals.partial} partial, {o.totals.gap} gap
          </button>
        ))}
        <button className="ghost-button" onClick={download}>Download PDF</button>
      </div>
      {report && (
        <div className="users-table">
          <div className="users-row compliance-row users-head"><span>Control</span><span>Status</span><span>What it asks</span><span>Evidence</span></div>
          {report.controls.map(c=>(
            <div className="users-row compliance-row" key={c.id}>
              <span>{c.id}</span>
              <span className={STATUS_CLASS[c.status]}>{c.status}</span>
              <span>{c.title}</span>
              <span className="audit-details">{c.evidence.length ? c.evidence.map(e=>`[${e.status}] ${e.summary}`).join(' · ') : 'organisational: evidence from outside the appliance'}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function OperationsModal({ open, onClose, user }){
  const [tab, setTab] = useState('response')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const [reloadKey, setReloadKey] = useState(0)

  const act = useCallback(async (fn, message)=>{
    setBusy(true)
    setError('')
    setNotice('')
    try{
      const out = await fn()
      setNotice(typeof message === 'function' ? message(out) : message)
      setReloadKey(k=>k + 1)
    }catch(e){
      setError(errorMessage(e))
    }finally{
      setBusy(false)
    }
  }, [])

  if(!open) return null
  const props = { user, act, busy, reloadKey }

  return (
    <div className="modal-backdrop">
      <section className="firewall-modal users-modal" role="dialog" aria-label="Operations">
        <div className="modal-header">
          <div>
            <h2>Operations</h2>
            <p>Approvals and restrictions, the response policy, two-node sensors, models and evaluation.</p>
          </div>
          <button className="icon-button" onClick={onClose}>Close</button>
        </div>
        <div className="audit-toolbar" role="tablist">
          {TABS.map(([k, label])=>(
            <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? 'primary-button' : 'ghost-button'} onClick={()=>{ setTab(k); setNotice(''); setError('') }}>{label}</button>
          ))}
          <button className="ghost-button" disabled={busy} onClick={()=>setReloadKey(k=>k + 1)}>Refresh</button>
        </div>
        {error && <div className="auth-error users-error" role="alert">{error}</div>}
        {notice && <div className="audit-integrity audit-ok" role="status">{notice}</div>}
        {tab === 'response' && <ResponseTab {...props} />}
        {tab === 'policy' && <PolicyTab {...props} />}
        {tab === 'sensors' && <SensorsTab {...props} />}
        {tab === 'models' && <ModelsTab {...props} />}
        {tab === 'compliance' && <ComplianceTab {...props} />}
      </section>
    </div>
  )
}
