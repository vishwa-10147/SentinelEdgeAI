import React, { useState, useEffect } from 'react'

export default function AnalyticsTrend({ timeline = [] }){
  const [R, setR] = useState(null)

  useEffect(()=>{
    let mounted = true
    import('recharts').then(mod=>{ if(mounted) setR(mod) }).catch(()=>{})
    return ()=>{ mounted = false }
  },[])

  if(!R){
    return (
      <article className="panel analytics-card">
        <div className="panel-header compact">
          <h2>Risk Score Trend</h2>
          <p>Recent telemetry</p>
        </div>
        <div style={{height:220,display:'flex',alignItems:'center',justifyContent:'center'}}>
          <span>Loading chart…</span>
        </div>
      </article>
    )
  }

  const { Area, AreaChart, CartesianGrid, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } = R

  return (
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
  )
}
