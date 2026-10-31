import React, { useCallback, useEffect, useState } from 'react'
import { apiGet, errorMessage } from '../api'

const PROTOCOLS = { modbus: 'Modbus/TCP', dnp3: 'DNP3', bacnet: 'BACnet/IP', opcua: 'OPC UA' }

function formatTime(ts){
  return ts ? new Date(ts * 1000).toLocaleString() : '—'
}

export default function OtModal({ open, onClose }){
  const [assets, setAssets] = useState([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async ()=>{
    setBusy(true)
    setError('')
    try{
      const body = await apiGet('/api/ot/assets', { assets: [] })
      setAssets(body.assets || [])
    }catch(e){
      setError(errorMessage(e))
    }finally{
      setBusy(false)
    }
  }, [])

  useEffect(()=>{ if(open) load() }, [open, load])

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
      </section>
    </div>
  )
}
