import React, { useState, useEffect } from 'react'

export default function AnalyticsPie({ severityData = [], onSeverityFilter = ()=>{} }){
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
          <h2>Severity Breakdown</h2>
          <p>Alert distribution</p>
        </div>
        <div style={{height:180,display:'flex',alignItems:'center',justifyContent:'center'}}>
          <span>Loading chart…</span>
        </div>
      </article>
    )
  }

  const { Pie, PieChart, ResponsiveContainer, Tooltip, Cell } = R

  return (
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
  )
}
