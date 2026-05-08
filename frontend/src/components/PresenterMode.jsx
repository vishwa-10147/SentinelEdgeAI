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
            const p = obj.payload || {}
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
    <div style={{position:'fixed', left:0, top:0, right:0, bottom:0, display:'flex', alignItems:'center', justifyContent:'center', pointerEvents:'none'}}>
      <div style={{pointerEvents:'auto', background:'rgba(0,0,0,0.7)', color:'#fff', padding:20, borderRadius:8, textAlign:'center', minWidth:420}}>
        <div style={{fontSize:18, fontWeight:700}}>{step || 'Demo'}</div>
        <div style={{marginTop:8, fontSize:14}}>{message}</div>
      </div>
    </div>
  )
}
