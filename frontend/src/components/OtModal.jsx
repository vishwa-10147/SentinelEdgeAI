import React, { useCallback, useEffect, useState } from 'react'
import { apiGet, apiPost, errorMessage, hasRole } from '../api'

const PROTOCOLS = { modbus: 'Modbus/TCP', dnp3: 'DNP3', bacnet: 'BACnet/IP', opcua: 'OPC UA' }

function formatTime(ts){
  return ts ? new Date(ts * 1000).toLocaleString() : '—'
}

const MODES = {
  off: 'Off: nothing installed.',
  monitor: 'Monitor: the plan below is shown; a new host commanding a controller is alerted.',
  enforce: 'Enforcing: only the allowed hosts can open connections to the guarded industrial ports.'
}

export default function OtModal({ open, onClose, user }){
  const [assets, setAssets] = useState([])
  const [seg, setSeg] = useState(null)
  const [exception, setException] = useState({ src: '', dst: '', protocol: 'modbus' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async ()=>{
    setBusy(true)
    setError('')
    try{
      const [body, segmentation] = await Promise.all([apiGet('/api/ot/assets', { assets: [] }), apiGet('/api/ot/segmentation', null)])
      setAssets(body.assets || [])
      setSeg(segmentation)
    }catch(e){
      setError(errorMessage(e))
    }finally{
      setBusy(false)
    }
  }, [])

  useEffect(()=>{ if(open) load() }, [open, load])

  const act = async (path, body)=>{
    setBusy(true)
    setError('')
    try{
      setSeg(await apiPost(path, body))
    }catch(e){
      setError(errorMessage(e))
    }finally{
      setBusy(false)
    }
  }

  const setMode = (mode)=>{
    if(mode === 'enforce' && !window.confirm('Enforce OT segmentation? Hosts that are not on a controller\'s allow-list will no longer reach its industrial ports.')) return
    act('/api/ot/segmentation', { mode })
  }

  const admin = hasRole(user, 'admin')

  if(!open) return null

  return (
    <div className="modal-backdrop">
      <section className="firewall-modal users-modal" role="dialog" aria-label="OT devices">
        <div className="modal-header">
          <div>
            <h2>OT devices</h2>
            <p>Industrial controllers seen on the network, the hosts that command them and the functions each host uses. After a controller's 7-day learning period, a new host or a first-time write is alerted.</p>
          </div>
          <button className="icon-button" onClick={onClose}>Close</button>
        </div>
        {error && <div className="auth-error users-error" role="alert">{error}</div>}
        <div className="rules-section">
          <div className="audit-toolbar">
            <button className="ghost-button" disabled={busy} onClick={load}>Refresh</button>
          </div>
          <div className="users-table">
            <div className="users-row ot-row users-head">
              <span>Controller</span><span>Protocol</span><span>First seen</span><span>Commanded by</span><span>Functions</span><span>Last seen</span>
            </div>
            {assets.map(a=>(a.masters.length ? a.masters : [{ ip: '—', functions: [], last_seen: null }]).map((m, i)=>(
              <div className="users-row ot-row" key={`${a.ip}-${a.protocol}-${m.ip}`}>
                <span>{i === 0 ? a.ip : ''}</span>
                <span>{i === 0 ? (PROTOCOLS[a.protocol] || a.protocol) : ''}</span>
                <span>{i === 0 ? formatTime(a.first_seen) : ''}</span>
                <span>{m.ip}</span>
                <span className="audit-details">{m.functions.join(', ') || '—'}</span>
                <span>{formatTime(m.last_seen)}</span>
              </div>
            )))}
            {!busy && assets.length === 0 && <p className="auth-hint">No Modbus, DNP3, BACnet or OPC UA traffic seen yet.</p>}
          </div>
        </div>
        {seg && (
          <div className="rules-section">
            <h3>Micro-segmentation</h3>
            <div className={seg.mode === 'enforce' ? 'audit-integrity audit-ok' : 'audit-integrity'} role="status">
              {MODES[seg.mode]}
              {seg.mode === 'enforce' && seg.dropped_packets != null && ` ${seg.dropped_packets} packets dropped.`}
              {seg.suspended && ` Turned off by "${seg.suspended.reason}".`}
              {!seg.inline && ' This device is passive, so it cannot enforce.'}
            </div>
            {admin && (
              <div className="audit-toolbar">
                {Object.keys(MODES).map(m=>(
                  <button key={m} className={m === seg.mode ? 'primary-button' : 'ghost-button'} disabled={busy || m === seg.mode || (m === 'enforce' && !seg.inline)} onClick={()=>setMode(m)}>{m}</button>
                ))}
                {seg.mode === 'enforce' && <button className="ghost-button" disabled={busy} onClick={()=>act('/api/ot/segmentation/refresh', {})} title="Take a new snapshot of the learned allow-lists">New snapshot</button>}
              </div>
            )}
            <div className="users-table">
              <div className="users-row ot-seg-row users-head"><span>Controller</span><span>Protocol</span><span>Allowed hosts</span></div>
              {(seg.plan?.controllers || []).map(c=>(
                <div className="users-row ot-seg-row" key={`${c.ip}-${c.protocol}`}>
                  <span>{c.ip}</span><span>{PROTOCOLS[c.protocol] || c.protocol}</span><span className="audit-details">{c.allowed.join(', ') || 'nobody'}</span>
                </div>
              ))}
              {(seg.plan?.learning || []).map(c=>(
                <div className="users-row ot-seg-row" key={`l-${c.ip}-${c.protocol}`}>
                  <span>{c.ip}</span><span>{PROTOCOLS[c.protocol] || c.protocol}</span><span className="auth-hint">learning until {formatTime(c.learned_at)}</span>
                </div>
              ))}
              {(seg.plan?.skipped || []).map(c=>(
                <div className="users-row ot-seg-row" key={`s-${c.ip}-${c.protocol}`}>
                  <span>{c.ip}</span><span>{PROTOCOLS[c.protocol] || c.protocol}</span><span className="auth-hint">never guarded ({c.reason})</span>
                </div>
              ))}
            </div>
            {admin && (
              <form className="audit-toolbar" onSubmit={e=>{ e.preventDefault(); act('/api/ot/segmentation/allow', exception) }}>
                <input placeholder="Host" value={exception.src} onChange={e=>setException({ ...exception, src: e.target.value })} aria-label="Host to allow" />
                <input placeholder="Controller" value={exception.dst} onChange={e=>setException({ ...exception, dst: e.target.value })} aria-label="Controller" />
                <select value={exception.protocol} onChange={e=>setException({ ...exception, protocol: e.target.value })} aria-label="Protocol">
                  {Object.entries(PROTOCOLS).map(([k, v])=><option key={k} value={k}>{v}</option>)}
                </select>
                <button className="ghost-button" disabled={busy || !exception.src || !exception.dst}>Add exception</button>
              </form>
            )}
          </div>
        )}
      </section>
    </div>
  )
}
