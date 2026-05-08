import React from 'react'

export default function Legend(){
  const items = [
    {label:'CRITICAL', color:'#FF3B30'},
    {label:'HIGH', color:'#FF9500'},
    {label:'MEDIUM', color:'#FFD60A'},
    {label:'LOW', color:'#34C759'},
    {label:'NORMAL', color:'#8E8E93'},
    {label:'BLOCKED', color:'#E74C3C'}
  ]
  return (
    <div className="se-legend" style={{position:'fixed', right:20, top:24, background:'rgba(7,16,24,0.95)', padding:12, borderRadius:8, color:'#E6EEF6'}}>
      <div style={{fontWeight:600, marginBottom:8}}>Risk Legend</div>
      {items.map(it=> (
        <div key={it.label} style={{display:'flex', alignItems:'center', gap:8, marginBottom:6}}>
          <div style={{width:14,height:14,background:it.color,borderRadius:4}} />
          <div style={{fontSize:12, color:'#C9D6E3'}}>{it.label}</div>
        </div>
      ))}
    </div>
  )
}
