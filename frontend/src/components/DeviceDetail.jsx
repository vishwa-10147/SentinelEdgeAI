import React, { useEffect, useMemo, useState } from 'react'
import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:9000'

function headers(){
  const key = sessionStorage.getItem('sentinel_api_key')
  return key ? { 'X-API-Key': key } : {}
}

function riskClass(risk){
  const score = Number(risk || 0)
  if(score >= 75) return 'critical'
  if(score >= 50) return 'high'
  if(score >= 25) return 'medium'
  return 'normal'
}

function formatTime(value){
  if(!value) return ''
  const date = typeof value === 'number' ? new Date(value * 1000) : new Date(value)
  if(Number.isNaN(date.getTime())) return String(value).slice(11, 19)
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export default function DeviceDetail({ deviceId, devices = [], alerts = [], flows = [], onClose, topologyApi, onFirewallChanged }){
  const [logs, setLogs] = useState([])
  const [undoUntil, setUndoUntil] = useState(null)
  const [now, setNow] = useState(Date.now())
  const [busy, setBusy] = useState(false)

  const device = useMemo(()=>{
    return devices.find(d=>d.id === deviceId || d.ip === deviceId || d.mac === deviceId) || {
      id: deviceId,
      ip: deviceId,
      hostname: deviceId,
      type: deviceId?.startsWith?.('192.168.') ? 'workstation' : 'external',
      risk: Math.max(0, ...alerts.filter(a=>a.src === deviceId || a.dst === deviceId).map(a=>a.risk))
    }
  }, [alerts, deviceId, devices])

  const relatedAlerts = useMemo(()=>{
    return alerts.filter(a=>a.src === device.id || a.dst === device.id || a.src === device.ip || a.dst === device.ip).slice(-30).reverse()
  }, [alerts, device])

  const relatedFlows = useMemo(()=>{
    return flows.filter(f=>f.src === device.id || f.dst === device.id || f.src === device.ip || f.dst === device.ip).slice(-20).reverse()
  }, [device, flows])

  const mitre = useMemo(()=>{
    const map = new Map()
    relatedAlerts.forEach(a=>{
      if(a.mitre_technique_id){
        map.set(a.mitre_technique_id, {
          id: a.mitre_technique_id,
          name: a.mitre_technique_name || 'Technique',
          tactic: a.mitre_tactic || 'Unknown'
        })
      }
    })
    ;(device.mitre || []).forEach(m=>{
      const id = m.technique_id || m.id
      if(id) map.set(id, { id, name: m.technique_name || m.name || 'Technique', tactic: m.tactic || 'Unknown' })
    })
    return Array.from(map.values())
  }, [device, relatedAlerts])

  useEffect(()=>{
    let mounted = true
    axios.get(`${API_BASE}/api/device/${encodeURIComponent(deviceId)}/logs`, { headers: headers() })
      .then(res=>{ if(mounted) setLogs(Array.isArray(res.data) ? res.data : []) })
      .catch(()=>{})
    return ()=>{ mounted = false }
  }, [deviceId])

  useEffect(()=>{
    const id = setInterval(()=>setNow(Date.now()), 1000)
    return ()=>clearInterval(id)
  }, [])

  const protocolSummary = Object.entries(device.protocol_usage || {}).sort((a,b)=>b[1]-a[1]).slice(0, 4)
  const behavior = device.behavior_summary || {}
  const commonPorts = device.common_ports || behavior.common_ports || []
  const typicalDestinations = device.typical_destinations || behavior.typical_destinations || []
  const undoSeconds = undoUntil ? Math.max(0, Math.ceil((undoUntil - now) / 1000)) : 0

  const quarantine = async ()=>{
    const ip = device.ip || device.id
    const typed = window.prompt(`Type CONFIRM to quarantine ${ip} for 300 seconds.`)
    if(typed !== 'CONFIRM') return
    setBusy(true)
    try{
      await axios.post(`${API_BASE}/api/firewall/block`, { ip, ttl: 300, reason: 'operator_quarantine' }, { headers: headers() })
      // show undo banner for the configured TTL (milliseconds)
      setUndoUntil(Date.now() + 300 * 1000)
      onFirewallChanged?.()
      window.dispatchEvent(new Event('se:firewall-changed'))
    }catch(e){
      window.dispatchEvent(new CustomEvent('se:toast', { detail: { type: 'error', message: `Quarantine failed for ${ip}` } }))
    }finally{
      setBusy(false)
    }
  }

  const unblock = async ()=>{
    const ip = device.ip || device.id
    setBusy(true)
    try{
      await axios.post(`${API_BASE}/api/firewall/unblock`, { ip }, { headers: headers() })
      setUndoUntil(null)
      onFirewallChanged?.()
      window.dispatchEvent(new Event('se:firewall-changed'))
    }finally{
      setBusy(false)
    }
  }

  const whitelist = async ()=>{
    const ip = device.ip || device.id
    const typed = window.prompt(`Type CONFIRM to whitelist ${ip}.`)
    if(typed !== 'CONFIRM') return
    setBusy(true)
    try{
      await axios.post(`${API_BASE}/api/firewall/whitelist`, { ip, action: 'add' }, { headers: headers() })
      onFirewallChanged?.()
      window.dispatchEvent(new Event('se:firewall-changed'))
    }finally{
      setBusy(false)
    }
  }

  return (
    <aside className="device-panel">
      <div className="device-panel-header">
        <div>
          <span className={`device-type ${riskClass(device.risk)}`}>{device.type || 'device'}</span>
          <h2>{device.hostname || device.ip || device.id}</h2>
          <p>{device.ip || device.id}{device.mac ? ` · ${device.mac}` : ''}</p>
        </div>
        <button className="icon-button" onClick={onClose}>Close</button>
      </div>

      <div className="risk-gauge-wrap">
        <div className={`risk-gauge ${riskClass(device.risk)}`} style={{ '--risk': Number(device.risk || 0) }}>
          <strong>{Number(device.risk || 0)}</strong>
          <span>Risk</span>
        </div>
        <div className="drift-state">
          <span className={device.drift || relatedAlerts.some(a=>a.drift) ? 'drifting' : ''} />
          {device.drift || relatedAlerts.some(a=>a.drift) ? 'Behavioral drift detected' : 'Behavior stable'}
        </div>
      </div>

      <section className="detail-section">
        <h3>Behavior Summary</h3>
        <div className="summary-grid">
          <div><span>Flows</span><strong>{device.flow_count || relatedFlows.length}</strong></div>
          <div><span>Packets</span><strong>{Number(device.total_packets || 0).toLocaleString()}</strong></div>
          <div><span>Normal avg bytes</span><strong>{Math.round(behavior.baseline_avg_bytes || device.baseline_avg_bytes || 0)}</strong></div>
          <div><span>Current avg bytes</span><strong>{Math.round(behavior.current_avg_bytes || 0)}</strong></div>
          <div><span>Avg packets/sec</span><strong>{behavior.avg_packets_per_sec || 0}</strong></div>
          <div><span>OS</span><strong>{device.os || 'Unknown'}</strong></div>
        </div>
        <p className="behavior-comparison">{behavior.comparison || 'Current behavior is being learned.'}</p>
        <div className="protocol-list">
          {protocolSummary.map(([name, count])=><span key={name}>{name} <b>{count}</b></span>)}
          {commonPorts.slice(0, 4).map(item=><span key={`port-${item.value}`}>Port {item.value} <b>{item.count}</b></span>)}
          {typicalDestinations.slice(0, 3).map(item=><span key={`dst-${item.value}`}>{item.value} <b>{item.count}</b></span>)}
        </div>
      </section>

      <section className="detail-section">
        <h3>MITRE Techniques</h3>
        <div className="mitre-chip-list">
          {mitre.length ? mitre.map(item=>(
            <a key={item.id} href={`https://attack.mitre.org/techniques/${String(item.id).replace('.', '/')}/`} target="_blank" rel="noreferrer">
              <strong>{item.id}</strong>
              <span>{item.name}</span>
            </a>
          )) : <p>No mapped techniques for this device.</p>}
        </div>
      </section>

      <section className="detail-section">
        <h3>Last Packets</h3>
        <div className="packet-table">
          {[...relatedAlerts, ...logs].slice(0, 20).map((row, i)=>(
            <div key={i}>
              <span>{formatTime(row.timestamp || row.logged_at)}</span>
              <strong>{row.src || row.initiator_ip || row.src_ip || device.ip} {'->'} {row.dst || row.responder_ip || row.dst_ip || ''}</strong>
              <em>{row.protocol || row.proto || ''}</em>
              <b>{row.risk || row.final_risk_score || ''}</b>
            </div>
          ))}
        </div>
      </section>

      <div className="device-actions">
        <button className="danger-button" onClick={quarantine} disabled={busy}>Quarantine</button>
        <button className="ghost-button" onClick={whitelist} disabled={busy}>Whitelist</button>
        <button className="ghost-button" onClick={()=>topologyApi?.zoomToDevice?.(device.id)}>Focus</button>
      </div>
      {undoSeconds > 0 && (
        <button className="undo-banner" onClick={unblock} disabled={busy}>
          Undo quarantine · {undoSeconds}s
        </button>
      )}
    </aside>
  )
}
