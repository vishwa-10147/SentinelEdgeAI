import React from 'react'
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

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

export default function AnalyticsRow({ timeline = [], alerts = [], devices = [], onSeverityFilter = ()=>{}, onSelectDevice = ()=>{} }){
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
