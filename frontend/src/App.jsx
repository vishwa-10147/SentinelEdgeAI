import React, { useCallback, useEffect, useMemo, useRef, useState, lazy, Suspense } from 'react'
import axios from 'axios'
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from 'recharts'
const Topology = lazy(() => import('./components/Topology'))
const DeviceDetail = lazy(() => import('./components/DeviceDetail'))
import PresenterMode from './components/PresenterMode'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:9000'
const SEVERITY = {
  NORMAL: { label: 'Normal', color: '#22c55e', className: 'normal' },
  LOW: { label: 'Low', color: '#22c55e', className: 'normal' },
  MEDIUM: { label: 'Medium', color: '#3b82f6', className: 'medium' },
  HIGH: { label: 'High', color: '#f59e0b', className: 'high' },
  CRITICAL: { label: 'Critical', color: '#ef4444', className: 'critical' },
  BLOCKED: { label: 'Blocked', color: '#991b1b', className: 'blocked' }
}

function getApiKey(){
  return sessionStorage.getItem('sentinel_api_key') || ''
}

function setApiKey(value){
  if(value) sessionStorage.setItem('sentinel_api_key', value)
  else sessionStorage.removeItem('sentinel_api_key')
}

function requestHeaders(){
  const key = getApiKey()
  return key ? { 'X-API-Key': key } : {}
}

async function apiGet(path, fallback){
  try{
    const res = await axios.get(API_BASE + path, { headers: requestHeaders() })
    return res.data ?? fallback
  }catch(e){
    return fallback
  }
}

async function apiPost(path, body = {}){
  const res = await axios.post(API_BASE + path, body, { headers: requestHeaders() })
  return res.data
}

function riskSeverity(score){
  const n = Number(score || 0)
  if(n >= 75) return 'CRITICAL'
  if(n >= 50) return 'HIGH'
  if(n >= 25) return 'MEDIUM'
  return 'NORMAL'
}

function normalizeDevices(raw, alerts = []){
  const map = new Map()
  const add = (id, value = {})=>{
    if(!id) return
    const existing = map.get(id) || {}
    const flowCount = value.flow_count ?? value.total_connections ?? existing.flow_count ?? 0
    const risk = Math.max(
      Number(existing.risk || 0),
      Number(value.risk || value.score || 0),
      flowCount ? Math.round(Number(value.risk_score_sum || 0) / Math.max(1, flowCount)) : 0
    )
    map.set(id, {
      id,
      ip: value.ip || id,
      hostname: value.hostname || value.name || value.host || `host-${String(id).split('.').pop()}`,
      mac: value.mac || '',
      type: value.type || inferDeviceType(id, value),
      os: value.os || value.os_fingerprint || 'Unknown',
      flow_count: flowCount,
      total_bytes: value.total_bytes || existing.total_bytes || 0,
      total_packets: value.total_packets || existing.total_packets || 0,
      protocol_usage: value.protocol_usage || existing.protocol_usage || {},
      baseline_avg_bytes: value.baseline_avg_bytes || existing.baseline_avg_bytes || 0,
      behavior_summary: value.behavior_summary || existing.behavior_summary || {},
      common_ports: value.common_ports || existing.common_ports || [],
      typical_destinations: value.typical_destinations || existing.typical_destinations || [],
      risk,
      drift: Boolean(value.drift || existing.drift),
      mitre: value.mitre || existing.mitre || []
    })
  }

  if(Array.isArray(raw)){
    raw.forEach((d, i)=> add(d.ip || d.id || d.mac || d.host || `dev-${i}`, d))
  }else if(raw && Array.isArray(raw.profiles)){
    raw.profiles.forEach((d, i)=> add(d.ip || d.id || d.mac || d.host || `dev-${i}`, d))
  }else if(raw && typeof raw === 'object'){
    Object.entries(raw).forEach(([ip, value])=> add(ip, { ip, ...(value || {}) }))
  }

  alerts.forEach((alert)=>{
    const src = alert.initiator_ip || alert.src_ip || alert.src
    const dst = alert.responder_ip || alert.dst_ip || alert.dst
    const risk = alert.final_risk_score || alert.risk || alert.score || 0
    const mitre = alert.mitre_technique_id ? [{
      technique_id: alert.mitre_technique_id,
      technique_name: alert.mitre_technique_name,
      tactic: alert.mitre_tactic
    }] : []
    add(src, { ip: src, risk, drift: alert.drift, mitre })
    add(dst, { ip: dst, risk: Math.max(0, Number(risk) - 10), mitre })
  })

  return Array.from(map.values()).sort((a,b)=> b.risk - a.risk)
}

function inferDeviceType(id, value){
  if(value.type) return value.type
  if(id === '0.0.0.0' || id === '127.0.0.1') return 'sensor'
  if(String(id).endsWith('.1')) return 'gateway'
  if(!String(id).startsWith('192.168.')) return 'external'
  return 'workstation'
}

function normalizeAlerts(raw){
  const list = Array.isArray(raw) ? raw : (raw && raw.alerts ? raw.alerts : [])
  return list.map((a, index)=>{
    const risk = Number(a.final_risk_score || a.risk || a.score || 0)
    const sev = String(a.severity || riskSeverity(risk)).toUpperCase()
    return {
      id: a.id || `${a.logged_at || a.timestamp || index}-${index}`,
      timestamp: a.logged_at || a.timestamp || a.time || '',
      src: a.initiator_ip || a.src_ip || a.src || a.device || 'unknown',
      dst: a.responder_ip || a.dst_ip || a.dst || 'unknown',
      protocol: a.protocol || a.proto || '',
      attack_type: a.attack_type || a.summary || a.reason || 'Anomalous flow',
      explanation: a.explanation || null,
      risk,
      severity: SEVERITY[sev] ? sev : riskSeverity(risk),
      drift: Boolean(a.drift),
      mitre_tactic: a.mitre_tactic || '',
      mitre_technique_id: a.mitre_technique_id || a.mitre_id || '',
      mitre_technique_name: a.mitre_technique_name || a.mitre_name || ''
    }
  })
}

function normalizeFlows(raw, alerts = []){
  const flows = raw && Array.isArray(raw.flows) ? raw.flows : (Array.isArray(raw) ? raw : [])
  const normalized = flows.map((f, i)=>({
    id: f.id || `flow-${i}`,
    src: f.src_ip || f.src || f.src_host || f.src_mac,
    dst: f.dst_ip || f.dst || f.dst_host || f.dst_mac,
    packets: Number(f.packets || f.total_packets || 1),
    bytes: Number(f.bytes || f.total_bytes || 0),
    protocol: f.protocol || f.proto || '',
    risk: Number(f.risk || f.score || f.final_risk_score || 0),
    drift: Boolean(f.drift)
  })).filter(f=>f.src && f.dst)

  const alertFlows = alerts.slice(-80).map((a, i)=>({
    id: `alert-flow-${i}`,
    src: a.src,
    dst: a.dst,
    packets: 1,
    bytes: 0,
    protocol: a.protocol,
    risk: a.risk,
    drift: a.drift
  })).filter(f=>f.src && f.dst && f.src !== 'unknown' && f.dst !== 'unknown')

  return [...normalized, ...alertFlows]
}

function normalizeTimeline(raw, liveStats){
  if(Array.isArray(raw)){
    return raw.map((p, i)=>({ name: formatShortTime(p.timestamp || p.time || i), risk: Number(p.risk || p.score || 0) })).slice(-120)
  }
  if(raw && typeof raw === 'object'){
    const points = []
    Object.values(raw).forEach((series)=>{
      if(Array.isArray(series)){
        series.forEach(p=>points.push({ timestamp: p.timestamp, risk: Number(p.risk || p.score || 0) }))
      }
    })
    if(points.length){
      return points.sort((a,b)=>Number(a.timestamp || 0)-Number(b.timestamp || 0)).slice(-120).map(p=>({
        name: formatShortTime(p.timestamp),
        risk: p.risk
      }))
    }
  }
  const history = liveStats && Array.isArray(liveStats.flow_history) ? liveStats.flow_history : []
  return history.slice(-120).map(p=>({ name: formatShortTime(p.timestamp), risk: Number(p.risk || p.score || 0) }))
}

function formatShortTime(value){
  if(!value) return ''
  const date = typeof value === 'number' ? new Date(value * 1000) : new Date(value)
  if(Number.isNaN(date.getTime())) return String(value).slice(11, 19)
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function formatFullTime(value){
  if(!value) return '--:--:--'
  const date = typeof value === 'number' ? new Date(value * 1000) : new Date(value)
  if(Number.isNaN(date.getTime())) return String(value).slice(11, 19) || String(value)
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function countsBySeverity(alerts){
  return alerts.reduce((acc, alert)=>{
    acc[alert.severity] = (acc[alert.severity] || 0) + 1
    return acc
  }, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, NORMAL: 0 })
}

function useUtcClock(){
  const [now, setNow] = useState(new Date())
  useEffect(()=>{
    const id = setInterval(()=>setNow(new Date()), 1000)
    return ()=>clearInterval(id)
  }, [])
  return now.toISOString().slice(11, 19)
}

function Sparkline({ values = [] }){
  const data = values.slice(-30)
  const max = Math.max(1, ...data)
  const points = data.map((v, i)=>{
    const x = data.length <= 1 ? 0 : (i / (data.length - 1)) * 58
    const y = 22 - (Number(v || 0) / max) * 20
    return `${x},${y}`
  }).join(' ')
  return (
    <svg className="sparkline" viewBox="0 0 60 24" aria-hidden="true">
      <polyline points={points || '0,22 60,22'} />
    </svg>
  )
}

function TopNav({ counts, enforcementMode, connected, criticalPulse, onPresenter, onOpenFirewall, onApiKey }){
  const utc = useUtcClock()
  return (
    <header className={`top-nav ${criticalPulse ? 'critical-pulse' : ''}`}>
      <div className="brand-block">
        <div className="shield-logo">S</div>
        <div>
          <div className="wordmark">SentinelEdgeAI</div>
          <div className="live-line"><span className={connected ? 'live-dot' : 'live-dot offline'} />{connected ? 'Live' : 'Reconnecting'} · Pi5 + Jetson Orin</div>
        </div>
      </div>
      <div className="nav-center">
        <div className="clock">{utc} UTC</div>
        <div className="nav-chip">eth0</div>
        <div className="nav-chip">capture: adaptive</div>
      </div>
      <div className="nav-actions">
        <span className="severity-pill critical">{counts.CRITICAL || 0} Critical</span>
        <span className="severity-pill high">{counts.HIGH || 0} High</span>
        <span className="severity-pill medium">{counts.MEDIUM || 0} Medium</span>
        <button className={`mode-badge ${enforcementMode === 'ENFORCING' ? 'enforcing' : ''}`} onClick={onOpenFirewall}>{enforcementMode}</button>
        <button className="ghost-button" onClick={onApiKey}>API Key</button>
        <button className="primary-button" onClick={onPresenter}>Start Presenter Demo</button>
      </div>
    </header>
  )
}

function KpiStrip({ devices, alerts, firewallRules, health, timeline, liveStats }){
  const counts = countsBySeverity(alerts)
  const peak = Math.max(0, ...alerts.slice(-100).map(a=>a.risk), ...devices.map(d=>d.risk || 0))
  const flowCount = liveStats.total_flows || liveStats.summary?.total_flows || 0
  const mttd = alerts.length ? Math.max(1, Math.round(alerts.slice(-30).reduce((sum, a)=>sum + (a.risk >= 75 ? 1.8 : a.risk >= 50 ? 3.4 : 4.6), 0) / Math.min(30, alerts.length))) : 0
  const points = timeline.map(p=>p.risk || 0)
  const cards = [
    { label: 'Flows processed', value: flowCount.toLocaleString(), tone: 'neutral', values: points },
    { label: 'Active devices', value: devices.length, tone: devices.length > 20 ? 'warning' : 'neutral', values: devices.map(d=>d.flow_count || 0).slice(0, 30) },
    { label: 'Total alerts', value: alerts.length, tone: alerts.length > 25 ? 'danger' : alerts.length > 10 ? 'warning' : 'neutral', values: alerts.slice(-30).map(a=>a.risk) },
    { label: 'Blocked IPs', value: firewallRules.length, tone: firewallRules.length ? 'danger' : 'good', values: firewallRules.map((_, i)=>i + 1) },
    { label: 'MTTD', value: mttd ? `${mttd}s` : '-', tone: mttd > 5 ? 'danger' : mttd > 2 ? 'warning' : 'good', values: points },
    { label: 'Risk score peak', value: peak, tone: riskSeverity(peak).toLowerCase(), values: points }
  ]
  return (
    <section className="kpi-strip">
      {cards.map(card=>(
        <article className={`kpi-card ${card.tone}`} key={card.label}>
          <div>
            <span>{card.label}</span>
            <strong>{card.value}</strong>
          </div>
          <Sparkline values={card.values} />
        </article>
      ))}
    </section>
  )
}

function AlertLog({ alerts, selectedSeverity, onFilter, search, onSearch, onSelectDevice, onExport }){
  const filtered = useMemo(()=>{
    return alerts.filter((alert)=>{
      const sevOk = selectedSeverity === 'ALL' || alert.severity === selectedSeverity
      const text = `${alert.src} ${alert.dst} ${alert.attack_type} ${alert.mitre_technique_id}`.toLowerCase()
      return sevOk && text.includes(search.toLowerCase())
    }).slice(-1000).reverse()
  }, [alerts, selectedSeverity, search])

  return (
    <section className="panel alert-panel">
      <div className="panel-header">
        <div>
          <h2>Live Alert Log</h2>
          <p>{filtered.length} visible events</p>
        </div>
        <button className="icon-button" onClick={onExport} title="Export alerts">Export</button>
      </div>
      <div className="filter-row">
        {['ALL','CRITICAL','HIGH','MEDIUM'].map(item=>(
          <button key={item} className={selectedSeverity === item ? 'active' : ''} onClick={()=>onFilter(item)}>{item === 'ALL' ? 'All' : SEVERITY[item].label}</button>
        ))}
        <input value={search} onChange={e=>onSearch(e.target.value)} placeholder="Search IP, attack, MITRE" />
      </div>
      <div className="alert-list">
        {filtered.map(alert=>(
          <button className={`alert-row ${SEVERITY[alert.severity].className}`} key={alert.id} onClick={()=>onSelectDevice(alert.src)}>
            <span className={`severity-badge ${SEVERITY[alert.severity].className}`}>{alert.severity}</span>
            <span className="alert-time">{formatFullTime(alert.timestamp)}</span>
            <span className="alert-route">{alert.src} {'->'} {alert.dst}</span>
            <span className="alert-attack" title={alert.explanation?.summary || alert.attack_type}>
              {alert.explanation?.summary || alert.attack_type}
            </span>
            <span className="alert-risk">Risk {alert.risk}</span>
            <span className="mitre-chip">{alert.mitre_technique_id || 'MITRE -'}</span>
          </button>
        ))}
      </div>
    </section>
  )
}

function MitrePanel({ alerts }){
  const rows = alerts.filter(a=>a.mitre_technique_id).slice(-10).reverse()
  return (
    <section className="panel mitre-panel">
      <div className="panel-header compact">
        <h2>MITRE ATT&CK</h2>
        <p>Last 10 mappings</p>
      </div>
      <div className="mitre-table">
        {rows.map((row, i)=>(
          <a
            key={`${row.id}-${i}`}
            href={`https://attack.mitre.org/techniques/${String(row.mitre_technique_id).replace('.', '/')}/`}
            target="_blank"
            rel="noreferrer"
            className={`mitre-row tactic-${String(row.mitre_tactic || 'unknown').toLowerCase().replace(/\s+/g, '-')}`}
          >
            <span>{row.mitre_technique_id}</span>
            <strong>{row.mitre_technique_name || 'Technique'}</strong>
            <em>{row.mitre_tactic || 'Unknown'}</em>
            <small>{row.src} · {formatFullTime(row.timestamp)}</small>
          </a>
        ))}
      </div>
    </section>
  )
}

function IncidentTimeline({ events, onSelectDevice }){
  return (
    <section className="panel incident-panel">
      <div className="panel-header compact">
        <h2>Incident Timeline</h2>
        <p>Recent sequence of flows, alerts, and response actions</p>
      </div>
      <div className="incident-list">
        {events.slice(-18).reverse().map((event, i)=>(
          <button key={`${event.timestamp}-${i}`} className={`incident-row ${event.type}`} onClick={()=>event.src && onSelectDevice(event.src)}>
            <span>{formatFullTime(event.timestamp)}</span>
            <strong>{event.label}</strong>
            <em>{event.src || ''}{event.dst ? ` -> ${event.dst}` : ''}</em>
            <b>{event.risk ? `Risk ${event.risk}` : event.type}</b>
          </button>
        ))}
      </div>
    </section>
  )
}

function AnalyticsRow({ timeline, alerts, devices, onSeverityFilter, onSelectDevice }){
  const severityData = Object.entries(countsBySeverity(alerts)).map(([name, value])=>({ name, value, color: SEVERITY[name].color }))
  const leaderboard = devices.slice().sort((a,b)=>b.risk-a.risk).slice(0, 10)
  return (
    <section className="analytics-row">
      <article className="panel analytics-card">
        <div className="panel-header compact">
          <h2>Risk Score Trend</h2>
          <p>Recent telemetry</p>
        </div>
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={timeline}>
            <defs>
              <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.65}/>
                <stop offset="95%" stopColor="#22c55e" stopOpacity={0.08}/>
              </linearGradient>
            </defs>
            <CartesianGrid stroke="#263244" strokeDasharray="3 3" />
            <XAxis dataKey="name" stroke="#64748b" minTickGap={24} />
            <YAxis stroke="#64748b" domain={[0, 100]} />
            <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #263244', color: '#e5edf7' }} />
            <ReferenceLine y={25} stroke="#3b82f6" strokeDasharray="3 3" />
            <ReferenceLine y={50} stroke="#f59e0b" strokeDasharray="3 3" />
            <ReferenceLine y={75} stroke="#ef4444" strokeDasharray="3 3" />
            <Area type="monotone" dataKey="risk" stroke="#00d4ff" fill="url(#riskGradient)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </article>

      <article className="panel analytics-card">
        <div className="panel-header compact">
          <h2>Severity Breakdown</h2>
          <p>Alert distribution</p>
        </div>
        <ResponsiveContainer width="100%" height={180}>
          <PieChart>
            <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={46} outerRadius={72} paddingAngle={3} onClick={(d)=>onSeverityFilter(d.name)}>
              {severityData.map(entry=><Cell key={entry.name} fill={entry.color} />)}
            </Pie>
            <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #263244', color: '#e5edf7' }} />
          </PieChart>
        </ResponsiveContainer>
        <div className="target-row">
          <span>MTTD <strong>&lt; 2s target</strong></span>
          <span>MTTR <strong>30s undo window</strong></span>
        </div>
      </article>

      <article className="panel analytics-card">
        <div className="panel-header compact">
          <h2>Device Risk Leaderboard</h2>
          <p>Top 10 devices</p>
        </div>
        <div className="leaderboard">
          {leaderboard.map((device, i)=>(
            <button key={device.id} onClick={()=>onSelectDevice(device.id)} className="leader-row">
              <span>{i + 1}</span>
              <strong>{device.ip}</strong>
              <em>{device.type}</em>
              <div className="risk-bar"><i style={{ width: `${Math.min(100, device.risk)}%`, background: SEVERITY[riskSeverity(device.risk)].color }} /></div>
              <b>{device.risk}</b>
            </button>
          ))}
        </div>
      </article>
    </section>
  )
}

function FirewallPolicyModal({ open, onClose, rules, onChanged }){
  const [policy, setPolicy] = useState({})
  const [actions, setActions] = useState([])
  const [confirmText, setConfirmText] = useState('')
  const [whitelistIp, setWhitelistIp] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async ()=>{
    if(!open) return
    const [p, a] = await Promise.all([
      apiGet('/api/firewall/policy', {}),
      apiGet('/api/firewall/actions', [])
    ])
    setPolicy(p || {})
    setActions(Array.isArray(a) ? a : [])
  }, [open])

  useEffect(()=>{ load() }, [load])

  if(!open) return null
  const mode = policy.enforcement_mode || policy.mode || 'DRY-RUN'
  const canEnforce = confirmText === 'CONFIRM'
  const updateMode = async ()=>{
    if(!canEnforce) return
    setBusy(true)
    try{
      await apiPost('/api/firewall/policy', { ...policy, enforcement_mode: mode === 'ENFORCING' ? 'DRY-RUN' : 'ENFORCING' })
      await load()
      onChanged()
    }finally{
      setBusy(false)
      setConfirmText('')
    }
  }
  const rollback = async ()=>{
    if(confirmText !== 'CONFIRM') return
    setBusy(true)
    try{
      await apiPost('/api/firewall/rollback', { reason: 'operator_emergency_rollback' })
      await load()
      onChanged()
    }finally{
      setBusy(false)
      setConfirmText('')
    }
  }
  const remove = async (ip)=>{
    setBusy(true)
    try{
      await apiPost('/api/firewall/unblock', { ip })
      await load()
      onChanged()
    }finally{
      setBusy(false)
    }
  }
  const whitelist = async ()=>{
    if(!whitelistIp) return
    setBusy(true)
    try{
      await apiPost('/api/firewall/whitelist', { ip: whitelistIp, action: 'add' })
      setWhitelistIp('')
      await load()
      onChanged()
    }finally{
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <section className="firewall-modal">
        <div className="modal-header">
          <div>
            <h2>Firewall Policy</h2>
            <p>Typed confirmation is required for destructive or enforcement changes.</p>
          </div>
          <button className="icon-button" onClick={onClose}>Close</button>
        </div>
        <div className="firewall-grid">
          <div className="policy-card">
            <label>Current enforcement mode</label>
            <div className={`enforcement-state ${mode === 'ENFORCING' ? 'enforcing' : ''}`}>{mode}</div>
            <label>Response mode</label>
            <div className="segmented-control">
              {['monitor','alert','auto_block'].map(item=>(
                <button
                  key={item}
                  className={(policy.response_mode || 'monitor') === item ? 'active' : ''}
                  disabled={busy}
                  onClick={async ()=>{
                    setBusy(true)
                    try{
                      await apiPost('/api/firewall/policy', { ...policy, response_mode: item })
                      await load()
                      onChanged()
                    }finally{
                      setBusy(false)
                    }
                  }}
                >
                  {item === 'auto_block' ? 'Auto-block' : item === 'alert' ? 'Alert' : 'Monitor'}
                </button>
              ))}
            </div>
            <input value={confirmText} onChange={e=>setConfirmText(e.target.value)} placeholder='Type "CONFIRM"' />
            <button disabled={!canEnforce || busy} className="primary-button" onClick={updateMode}>Switch mode</button>
          </div>
          <div className="policy-card">
            <label>Whitelist management</label>
            <input value={whitelistIp} onChange={e=>setWhitelistIp(e.target.value)} placeholder="Add IPv4 address" />
            <button disabled={busy || !whitelistIp} className="ghost-button" onClick={whitelist}>Add whitelist</button>
          </div>
          <div className="policy-card danger-zone">
            <label>Emergency rollback</label>
            <p>Remove all current blocks immediately.</p>
            <button disabled={confirmText !== 'CONFIRM' || busy} onClick={rollback}>Remove ALL blocks now</button>
          </div>
        </div>
        <div className="rules-section">
          <h3>Active block rules</h3>
          <div className="rules-table">
            {(rules || []).map((rule, i)=>(
              <div className="rule-row" key={`${rule.ip || rule.target}-${i}`}>
                <span>{rule.ip || rule.target}</span>
                <em>{rule.reason || 'policy'}</em>
                <small>{rule.remaining_ttl ? `${rule.remaining_ttl}s` : rule.ttl ? `${rule.ttl}s` : 'manual'}</small>
                <button onClick={()=>remove(rule.ip || rule.target)} disabled={busy}>Remove</button>
              </div>
            ))}
          </div>
        </div>
        <div className="rules-section">
          <h3>Audit log</h3>
          <div className="audit-list">
            {actions.slice(-50).reverse().map((a, i)=>(
              <div key={i}><span>{a.timestamp || ''}</span><strong>{a.action || 'action'}</strong><em>{a.ip || a.target || ''}</em></div>
            ))}
          </div>
        </div>
      </section>
    </div>
  )
}

export default function App(){
  const [rawDevices, setRawDevices] = useState({})
  const [liveStats, setLiveStats] = useState({})
  const [rawAlerts, setRawAlerts] = useState([])
  const [rawTimeline, setRawTimeline] = useState({})
  const [incidentEvents, setIncidentEvents] = useState([])
  const [firewallRules, setFirewallRules] = useState([])
  const [health, setHealth] = useState({})
  const [selected, setSelected] = useState(null)
  const [topologyApi, setTopologyApi] = useState(null)
  const [filter, setFilter] = useState('ALL')
  const [search, setSearch] = useState('')
  const [firewallOpen, setFirewallOpen] = useState(false)
  const [connected, setConnected] = useState(false)
  const [criticalPulse, setCriticalPulse] = useState(false)
  const [toast, setToast] = useState(null)
  const lastAlertId = useRef(null)

  const alerts = useMemo(()=>normalizeAlerts(rawAlerts), [rawAlerts])
  const devices = useMemo(()=>normalizeDevices(rawDevices, alerts), [rawDevices, alerts])
  const flows = useMemo(()=>normalizeFlows(liveStats, alerts), [liveStats, alerts])
  const timeline = useMemo(()=>normalizeTimeline(rawTimeline, liveStats), [rawTimeline, liveStats])
  const counts = useMemo(()=>countsBySeverity(alerts), [alerts])
  const enforcementMode = health.enforcement_mode || health.firewall_mode || 'DRY-RUN'

  const loadAll = useCallback(async ()=>{
    const [d, f, a, fw, h, rt] = await Promise.all([
      apiGet('/api/device_profiles', {}),
      apiGet('/api/live_stats', {}),
      apiGet('/api/alerts', []),
      apiGet('/api/firewall/rules', []),
      apiGet('/api/health', {}),
      apiGet('/api/risk_timeline', {})
    ])
    setRawDevices(d || {})
    setLiveStats(f || {})
    setRawAlerts(a || [])
    setFirewallRules(Array.isArray(fw) ? fw : [])
    setHealth(h || {})
    setRawTimeline(rt || {})
    const incidents = await apiGet('/api/incidents/timeline', [])
    setIncidentEvents(Array.isArray(incidents) ? incidents : [])
  }, [])

  useEffect(()=>{
    loadAll()
    const id = setInterval(loadAll, 8000)
    const onFw = ()=>loadAll()
    const onToast = (event)=>showToast(event.detail?.message || 'Dashboard event', event.detail?.type || 'info')
    window.addEventListener('se:firewall-changed', onFw)
    window.addEventListener('se:toast', onToast)
    return ()=>{
      clearInterval(id)
      window.removeEventListener('se:firewall-changed', onFw)
      window.removeEventListener('se:toast', onToast)
    }
  }, [loadAll])

  useEffect(()=>{
    let ws
    let reconnect
    let closed = false
    const connect = ()=>{
      ws = new WebSocket(API_BASE.replace(/^http/, 'ws') + '/ws/packets')
      ws.onopen = ()=>setConnected(true)
      ws.onclose = ()=>{
        setConnected(false)
        if(!closed) reconnect = setTimeout(connect, 2000)
      }
      ws.onerror = ()=>setConnected(false)
      ws.onmessage = (event)=>{
        try{
          const msg = JSON.parse(event.data)
          const payload = msg.payload || {}
          if(msg.type === 'alert'){
            const normalized = normalizeAlerts([payload])[0]
            if(normalized && normalized.id !== lastAlertId.current){
              lastAlertId.current = normalized.id
              setRawAlerts(prev=>[...normalizeAlerts(prev), normalized].slice(-3000))
              if(normalized.severity === 'CRITICAL'){
                setCriticalPulse(true)
                setTimeout(()=>setCriticalPulse(false), 900)
              }
            }
          }else if(msg.type === 'flow'){
            setLiveStats(prev=>({ ...(prev || {}), flows: [...((prev && prev.flows) || []), payload].slice(-300) }))
            setIncidentEvents(prev=>[...prev, {
              timestamp: payload.timestamp,
              type: 'flow',
              label: Number(payload.risk || 0) >= 75 ? 'Risk spike' : Number(payload.risk || 0) > 0 ? 'Suspicious flow' : 'Normal traffic',
              risk: Number(payload.risk || 0),
              src: payload.src,
              dst: payload.dst
            }].slice(-200))
          }else if(msg.type === 'health_event'){
            setHealth(payload)
          }else if(msg.type === 'firewall_event'){
            loadAll()
          }
        }catch(e){}
      }
    }
    connect()
    return ()=>{ closed = true; if(reconnect) clearTimeout(reconnect); if(ws) ws.close() }
  }, [loadAll])

  const showToast = (message, type = 'info')=>{
    setToast({ message, type })
    setTimeout(()=>setToast(null), 3500)
  }

  const startPresenter = async ()=>{
    try{
      await apiPost('/api/demo/presenter', { simulate_type: 'portscan' })
      showToast('Presenter demo started', 'success')
    }catch(e){
      showToast('Presenter demo failed', 'error')
    }
  }

  const configureApiKey = ()=>{
    const current = getApiKey()
    const value = window.prompt('Enter dashboard API key for this tab. Leave blank to clear.', current)
    if(value === null) return
    setApiKey(value.trim())
    loadAll()
  }

  const exportAlerts = ()=>{
    const blob = new Blob([JSON.stringify(alerts, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'alerts.json'
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  const generateReport = async ()=>{
    try{
      const report = await apiGet('/api/reports/security', null)
      if(!report) throw new Error('empty report')
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `sentineledgeai-security-report-${new Date().toISOString().slice(0, 10)}.json`
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
      showToast('Security report generated', 'success')
    }catch(e){
      showToast('Report generation failed', 'error')
    }
  }

  return (
    <div className="soc-app">
      <TopNav
        counts={counts}
        enforcementMode={enforcementMode}
        connected={connected}
        criticalPulse={criticalPulse}
        onPresenter={startPresenter}
        onOpenFirewall={()=>setFirewallOpen(true)}
        onApiKey={configureApiKey}
      />
      <main className="dashboard-shell">
        <KpiStrip devices={devices} alerts={alerts} firewallRules={firewallRules} health={health} timeline={timeline} liveStats={liveStats} />
        <section className="main-grid">
          <section className="panel topology-shell">
            <div className="panel-header">
              <div>
                <h2>Network Topology</h2>
                <p>Click a host for behavior details. Blocked flows stop at the midpoint.</p>
              </div>
              <div className="topology-tools">
                <button className="ghost-button" onClick={generateReport}>Generate Security Report</button>
                <button className="ghost-button" onClick={()=>topologyApi?.fit?.()}>Fit</button>
                <button className="ghost-button" onClick={async ()=>{
                  const data = await topologyApi?.exportSnapshot?.()
                  if(data){
                    const a = document.createElement('a')
                    a.href = data
                    a.download = 'sentineledgeai-topology.png'
                    document.body.appendChild(a)
                    a.click()
                    a.remove()
                  }
                }}>Snapshot</button>
              </div>
            </div>
            <Suspense fallback={<div className="panel loading">Loading topology     </div>}>
              <Topology devices={devices} flows={flows} alerts={alerts} firewallRules={firewallRules} onSelectDevice={setSelected} onMount={setTopologyApi} />
            </Suspense>
          </section>
          <aside className="right-rail">
            <AlertLog
              alerts={alerts}
              selectedSeverity={filter}
              onFilter={setFilter}
              search={search}
              onSearch={setSearch}
              onSelectDevice={(id)=>{ setSelected(id); topologyApi?.zoomToDevice?.(id) }}
              onExport={exportAlerts}
            />
            <MitrePanel alerts={alerts} />
            <IncidentTimeline events={incidentEvents} onSelectDevice={(id)=>{ setSelected(id); topologyApi?.zoomToDevice?.(id) }} />
          </aside>
        </section>
        <AnalyticsRow timeline={timeline} alerts={alerts} devices={devices} onSeverityFilter={setFilter} onSelectDevice={(id)=>{ setSelected(id); topologyApi?.zoomToDevice?.(id) }} />
      </main>
      {selected && (
        <Suspense fallback={<div className="panel loading">Loading device details...</div>}>
          <DeviceDetail deviceId={selected} devices={devices} alerts={alerts} flows={flows} onClose={()=>setSelected(null)} topologyApi={topologyApi} onFirewallChanged={loadAll} />
        </Suspense>
      )}
      <FirewallPolicyModal open={firewallOpen} onClose={()=>setFirewallOpen(false)} rules={firewallRules} onChanged={loadAll} />
      <PresenterMode />
      {toast && <div className={`toast ${toast.type}`}>{toast.message}</div>}
    </div>
  )
}
