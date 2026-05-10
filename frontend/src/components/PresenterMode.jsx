import React, { useEffect, useState } from 'react'

export default function PresenterMode(){
  const [active, setActive] = useState(false)
  const [step, setStep] = useState(null)
  const [message, setMessage] = useState('')

  useEffect(()=>{
    let ws = null
    try{
      const base = (import.meta.env.VITE_API_BASE || 'http://localhost:9000').replace('http','ws')
      ws = new WebSocket(base + '/ws/packets')
      ws.onmessage = (ev)=>{
        try{
          const obj = JSON.parse(ev.data)
          if(obj.type === 'demo_step'){
            const p = (obj.payload && obj.payload.payload) || obj.payload || {}
            setActive(true)
            setStep(p.step)
            setMessage(p.message || '')
            if(p.step === 'demo_end'){
              setTimeout(()=>{ setActive(false); setStep(null); setMessage('') }, 1500)
            }
          }
        }catch(e){}
      }
    }catch(e){ console.warn('presenter ws failed', e) }
    return ()=>{ if(ws) ws.close() }
  },[])

  if(!active) return null
  return (
    <div style={{position:'fixed', left:0, top:68, right:0, pointerEvents:'none', zIndex:10002, display:'flex', justifyContent:'center'}}>
      <div style={{pointerEvents:'auto', background:'rgba(15,23,42,0.94)', color:'#fff', padding:'12px 20px', borderRadius:8, textAlign:'center', minWidth:420, border:'1px solid rgba(0,212,255,0.45)', boxShadow:'0 18px 60px rgba(0,0,0,0.35)'}}>
        <div style={{fontSize:14, fontWeight:800, color:'#00d4ff'}}>{step || 'Demo'}</div>
        <div style={{marginTop:4, fontSize:13}}>{message}</div>
      </div>
    </div>
  )
}
