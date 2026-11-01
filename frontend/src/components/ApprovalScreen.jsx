import React, { useEffect, useState } from 'react'
import { apiGet, apiPost, errorMessage, hasRole } from '../api'
import { AuthCard } from './AuthScreens'

function formatTime(ts){
  return ts ? new Date(ts * 1000).toLocaleString() : '—'
}

// Opened from an approval notification (e-mail, Slack, Teams) at #approve/<id>; built for a phone screen.
export default function ApprovalScreen({ id, user, onDone }){
  const [item, setItem] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState('')

  useEffect(()=>{
    apiGet(`/api/playbook/pending/${id}`, null).then(setItem).catch(e=>setError(errorMessage(e, 'This request could not be loaded.')))
  }, [id])

  const decide = async (approve)=>{
    if(!approve && !window.confirm(`Deny ${item.action} on ${item.ip}? Nothing will be applied.`)) return
    setBusy(true)
    setError('')
    try{
      const r = await apiPost(`/api/playbook/pending/${id}/${approve ? 'approve' : 'deny'}`, {})
      setResult(approve ? `Approved: ${r.action} on ${r.ip} (${r.status}).` : `Denied: nothing was applied to ${r.ip}.`)
      setItem({ ...item, status: r.status, decided_by: user.username })
    }catch(e){
      setError(errorMessage(e))
    }finally{
      setBusy(false)
    }
  }

  const operator = hasRole(user, 'operator')
  return (
    <AuthCard title="Approval request" subtitle={item ? `Requested ${formatTime(item.created)}` : 'Loading…'}>
      {item && (
        <div className="approval-body">
          <p className="approval-action">{item.action} <strong>{item.ip}</strong>{item.ttl ? ` for ${Math.round(item.ttl / 60)} min` : ''}</p>
          <p>Risk <strong>{item.risk}</strong></p>
          <p className="auth-hint">Reason: {item.reason || '—'}</p>
          {item.status !== 'pending' && (
            <p className="audit-integrity" role="status">Already {item.status}{item.decided_by ? ` by ${item.decided_by}` : ''}{item.decided ? ` at ${formatTime(item.decided)}` : ''}.</p>
          )}
          {item.status === 'pending' && operator && (
            <div className="approval-buttons">
              <button className="primary-button" disabled={busy} onClick={()=>decide(true)}>Approve</button>
              <button className="ghost-button" disabled={busy} onClick={()=>decide(false)}>Deny</button>
            </div>
          )}
          {item.status === 'pending' && !operator && <p className="auth-hint">Only an Operator or Admin can decide. You are signed in as {user.role}.</p>}
        </div>
      )}
      {result && <p className="audit-integrity audit-ok" role="status">{result}</p>}
      {error && <div className="auth-error" role="alert">{error}</div>}
      <button className="ghost-button" onClick={onDone}>Open the console</button>
    </AuthCard>
  )
}
