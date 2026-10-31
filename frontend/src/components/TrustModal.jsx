import React, { useCallback, useEffect, useState } from 'react'
import { apiGet, apiPost, errorMessage, hasRole } from '../api'

const LEVEL_CLASS = { trusted: 'mfa-on', watch: 'mfa-pending', untrusted: 'trust-untrusted' }

export default function TrustModal({ open, onClose, user }){
  const [devices, setDevices] = useState([])
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async ()=>{
    setBusy(true)
    setError('')
    try{
      const body = await apiGet('/api/trust', { devices: [] })
      setDevices(body.devices || [])
    }catch(e){
      setError(errorMessage(e))
    }finally{
      setBusy(false)
    }
  }, [])

  useEffect(()=>{ if(open) load() }, [open, load])

  const contain = async (ip, release)=>{
    if(!release && !window.confirm(`Contain ${ip}? It keeps only the peers and ports it normally uses (plus DNS and DHCP) for one hour.`)) return
    setBusy(true)
    setError('')
    setNotice('')
    try{
      if(release) await apiPost('/api/firewall/release', { kind: 'contain', ip })
      else await apiPost('/api/firewall/contain', { ip, ttl: 3600, reason: 'low trust score' })
      setNotice(release ? `${ip} released.` : `${ip} contained to its learned peers.`)
      await load()
    }catch(e){
      setError(errorMessage(e))
      setBusy(false)
    }
  }

  const operator = hasRole(user, 'operator')

  if(!open) return null

  return (
    <div className="modal-backdrop">
      <section className="firewall-modal users-modal" role="dialog" aria-label="Device trust">
        <div className="modal-header">
          <div>
            <h2>Device trust</h2>
            <p>Each device's trust score (0–100) from its identity, how long it has been seen and its recent alerts. Alerts an analyst marked as false positives don't count. An untrusted device can be contained to the peers and ports it normally uses instead of being cut off.</p>
          </div>
          <button className="icon-button" onClick={onClose}>Close</button>
        </div>
        {error && <div className="auth-error users-error" role="alert">{error}</div>}
        {notice && <div className="audit-integrity audit-ok" role="status">{notice}</div>}
        <div className="rules-section">
          <div className="audit-toolbar">
            <button className="ghost-button" disabled={busy} onClick={load}>Refresh</button>
          </div>
          <div className="users-table">
            <div className="users-row trust-row users-head">
              <span>Device</span><span>Score</span><span>Level</span><span>Why</span><span>Recommended</span><span></span>
            </div>
            {devices.map(d=>(
              <div className="users-row trust-row" key={d.ip}>
                <span>{d.ip}</span>
                <span>{d.score}</span>
                <span className={LEVEL_CLASS[d.level]}>{d.level}</span>
                <span className="audit-details">{d.reasons.join('; ')}</span>
                <span>{d.recommendation}</span>
                <span>
                  {operator && d.recommendation === 'contain' && <button className="ghost-button" disabled={busy} onClick={()=>contain(d.ip, false)}>Contain</button>}
                  {operator && d.reasons.includes('currently contained to its learned peers') && <button className="ghost-button" disabled={busy} onClick={()=>contain(d.ip, true)}>Release</button>}
                </span>
              </div>
            ))}
            {!busy && devices.length === 0 && <p className="auth-hint">No devices seen yet.</p>}
          </div>
        </div>
      </section>
    </div>
  )
}
