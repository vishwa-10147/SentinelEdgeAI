import React, { lazy, Suspense } from 'react'
const AnalyticsTrend = lazy(() => import('./AnalyticsTrend'))
const AnalyticsPie = lazy(() => import('./AnalyticsPie'))

const SEVERITY = {
  NORMAL: { label: 'Normal', color: '#22c55e', className: 'normal' },
  LOW: { label: 'Low', color: '#22c55e', className: 'normal' },
  MEDIUM: { label: 'Medium', color: '#3b82f6', className: 'medium' },
  HIGH: { label: 'High', color: '#f59e0b', className: 'high' },
  CRITICAL: { label: 'Critical', color: '#ef4444', className: 'critical' },
  BLOCKED: { label: 'Blocked', color: '#991b1b', className: 'blocked' }
}

function riskSeverity(score){
  const n = Number(score || 0)
  if(n >= 75) return 'CRITICAL'
  if(n >= 50) return 'HIGH'
  if(n >= 25) return 'MEDIUM'
  return 'NORMAL'
}

function countsBySeverity(alerts){
  return alerts.reduce((acc, alert)=>{
    acc[alert.severity] = (acc[alert.severity] || 0) + 1
    return acc
  }, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, NORMAL: 0 })
}

export default function AnalyticsPanel({ timeline = [], alerts = [], devices = [], onSeverityFilter = ()=>{}, onSelectDevice = ()=>{} }){
  const severityData = Object.entries(countsBySeverity(alerts)).map(([name, value])=>({ name, value, color: SEVERITY[name].color }))
  const leaderboard = devices.slice().sort((a,b)=>b.risk-a.risk).slice(0, 10)
  return (
    <section className="analytics-row">
      <Suspense fallback={<div style={{padding:20,color:'#94a3b8'}}>Loading charts…</div>}>
        <AnalyticsTrend timeline={timeline} />
        <AnalyticsPie severityData={severityData} onSeverityFilter={onSeverityFilter} />
      </Suspense>

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
