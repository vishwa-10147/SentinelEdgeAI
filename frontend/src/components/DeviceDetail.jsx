import React, { useEffect, useState, useRef } from 'react'
import axios from 'axios'

export default function DeviceDetail({ deviceId, onClose, topologyApi }){
  const [logs, setLogs] = useState([])
  const [summary, setSummary] = useState({})
  const [threat, setThreat] = useState(null)
  const [blocked, setBlocked] = useState(false)
  const [undoVisible, setUndoVisible] = useState(false)
  const undoTimerRef = useRef(null)
  const wsRef = useRef(null)

  useEffect(()=>{
    const base = import.meta.env.VITE_API_BASE || 'http://localhost:9000'
    let mounted = true
    const fetchSummary = async ()=>{
      try{
        const s = await axios.get(base + '/api/device_profiles')
        // try to find device by id
        const devs = s.data || []
        const dev = Array.isArray(devs) ? devs.find(d=>d.mac===deviceId||d.id===deviceId||d.host===deviceId) : null
        if(dev && mounted) setSummary(dev)
      }catch(e){ console.error(e) }
    }
    fetchSummary()

    // websocket for live packet logs
    try{
      const wsUrl = (import.meta.env.VITE_API_BASE || 'http://localhost:9000').replace('http','ws') + '/ws/packets'
      const ws = new WebSocket(wsUrl)
      ws.onmessage = (ev)=>{
        try{
          const obj = JSON.parse(ev.data)
          // websocket events are {type:'alert'|'flow', payload: {...}}
          const payload = obj.payload || obj
          const match = (payload.src===deviceId || payload.dst===deviceId || payload.src_mac===deviceId || payload.dst_mac===deviceId || JSON.stringify(payload).includes(deviceId))
          if(match){
            setLogs(prev=>[payload,...prev].slice(0,200))
          }
        }catch(e){}
      }
      wsRef.current = ws
    }catch(e){ console.warn('ws failed', e) }

    return ()=>{ mounted=false; if(wsRef.current) wsRef.current.close() }
  },[deviceId])

  // fetch firewall actions for this device
  useEffect(()=>{
    const base = import.meta.env.VITE_API_BASE || 'http://localhost:9000'
    let mounted = true
    const fetchActions = async ()=>{
      try{
        const r = await axios.get(base + '/api/firewall/actions')
        if(mounted) setThreat(r.data || [])
      }catch(e){}
    }
    fetchActions()
    const t = setInterval(fetchActions, 5000)
    return ()=>{ mounted=false; clearInterval(t) }
  },[deviceId])

  return (
    <div style={{position:'fixed', right:20, top:80, width:480, height:'75vh', background:'#0F1720', color:'#fff', borderRadius:8, boxShadow:'0 8px 30px rgba(0,0,0,0.6)', overflow:'hidden'}}>
      <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', padding:12, borderBottom:'1px solid rgba(255,255,255,0.04)'}}>
        <div>
          <div style={{fontSize:16, fontWeight:600}}>{summary.host||summary.name||deviceId}</div>
          <div style={{fontSize:12, color:'#AAB2BD'}}>{summary.ip||summary.mac||''}</div>
        </div>
        <div>
          <button onClick={onClose} style={{background:'transparent',border:'none',color:'#AAB2BD',cursor:'pointer'}}>Close</button>
          {topologyApi && <button onClick={()=>topologyApi.zoomToDevice(deviceId)} style={{marginLeft:8, padding:'6px 8px'}}>Zoom</button>}
          {topologyApi && <button onClick={async ()=>{
            const data = await topologyApi.exportSnapshot()
            if(data){
              const a = document.createElement('a')
              a.href = data
              a.download = `${deviceId}-snapshot.png`
              document.body.appendChild(a)
              a.click()
              a.remove()
            }
          }} style={{marginLeft:8, padding:'6px 8px'}}>Export</button>}
        </div>
      </div>
      <div style={{display:'flex', height:'100%'}}>
        <div style={{flex:1, borderRight:'1px solid rgba(255,255,255,0.03)', overflow:'auto'}}>
          <h3 style={{padding:12, margin:0}}>Packet Logs</h3>
          <table style={{width:'100%', borderCollapse:'collapse'}}>
            <thead style={{position:'sticky', top:0, background:'#0F1720'}}>
              <tr style={{color:'#AAB2BD', fontSize:12}}>
                <th style={{textAlign:'left', padding:8}}>Time</th>
                <th style={{textAlign:'left', padding:8}}>Src → Dst</th>
                <th style={{textAlign:'left', padding:8}}>Proto</th>
                <th style={{textAlign:'left', padding:8}}>Port</th>
                <th style={{textAlign:'left', padding:8}}>Risk</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((l,i)=>{
                const risk = l.risk||0
                const bg = risk>=75 ? 'rgba(231,76,60,0.06)' : 'transparent'
                return (
                <tr key={i} style={{background: bg}}>
                  <td style={{padding:8, fontSize:12}}>{l.timestamp ? new Date(l.timestamp*1000).toLocaleTimeString() : ''}</td>
                  <td style={{padding:8, fontSize:12}}>{l.src || l.src_ip || ''} → {l.dst || l.dst_ip || ''}</td>
                  <td style={{padding:8, fontSize:12}}>{l.proto || l.protocol || ''}</td>
                  <td style={{padding:8, fontSize:12}}>{l.port||''}</td>
                  <td style={{padding:8, fontSize:12}}><span style={{padding:'4px 8px', borderRadius:12, background: risk>=75 ? '#E74C3C' : risk>=50 ? '#F1C40F' : '#27AE60'}}>{risk}</span></td>
                </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        <div style={{width:260, padding:12}}>
          <h3 style={{marginTop:0}}>Behavior Summary</h3>
          <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:8}}>
            <div style={{background:'#0B1116', padding:8, borderRadius:6}}>
              <div style={{fontSize:12,color:'#AAB2BD'}}>Total connections</div>
              <div style={{fontSize:18,fontWeight:600}}>{summary.total_connections||0}</div>
            </div>
            <div style={{background:'#0B1116', padding:8, borderRadius:6}}>
              <div style={{fontSize:12,color:'#AAB2BD'}}>Unique dests</div>
              <div style={{fontSize:18,fontWeight:600}}>{summary.unique_dests||0}</div>
            </div>
          </div>

          <h3>Threat Info</h3>
          <div style={{background:'#071018', padding:8, borderRadius:6}}>
            <div style={{fontSize:14, fontWeight:700}}>{summary.threat_type||'None'}</div>
            <div style={{fontSize:12, color:'#AAB2BD', marginTop:6}}>{summary.threat_summary||'No active threat'}</div>
            <div style={{marginTop:8}}>
                {summary.mitre && Array.isArray(summary.mitre) && summary.mitre.map((m,i)=> (
                <div key={i} style={{display:'inline-block', background:'#0B1116', padding:'6px 8px', borderRadius:6, marginRight:6, marginTop:6, fontSize:12}}>
                  <div style={{fontWeight:700}}>{m.technique_name || m.name || m.technique}</div>
                  <div style={{fontSize:11, color:'#AAB2BD'}}>{m.technique_id || m.id || ''}</div>
                </div>
              ))}
            </div>
            <div style={{marginTop:8}}>
              <button style={{background:'#E74C3C', color:'#fff', border:'none', padding:'8px 12px', borderRadius:6}} onClick={async ()=>{
                const ip = summary.ip || deviceId
                const payload = { title: 'Confirm Quarantine', message: `Quarantine ${ip}? This will request the AI firewall to block traffic from this device (dry-run by default).`, payload: { ip } }
                // listen for modal result once
                const onResult = async (e)=>{
                  const ok = e.detail && e.detail.ok
                  if(ok){
                    try{
                      const base = import.meta.env.VITE_API_BASE || 'http://localhost:9000'
                      await axios.post(base + '/api/firewall/block', { ip, ttl:300, reason:'operator action' })
                      window.dispatchEvent(new Event('se:firewall-changed'))
                      setBlocked(true)
                      setUndoVisible(true)
                      window.dispatchEvent(new CustomEvent('se:toast', { detail: { type:'success', message: `Quarantine requested for ${ip}` } }))
                      if(undoTimerRef.current) clearTimeout(undoTimerRef.current)
                      undoTimerRef.current = setTimeout(()=>{ setUndoVisible(false); undoTimerRef.current = null }, 30000)
                    }catch(e){ window.dispatchEvent(new CustomEvent('se:toast', { detail: { type:'error', message: 'Block failed' } })) }
                  }
                  window.removeEventListener('se:modal-result', onResult)
                }
                window.addEventListener('se:modal-result', onResult)
                window.dispatchEvent(new CustomEvent('se:modal', { detail: payload }))
              }}>Quarantine</button>
              {undoVisible && (
                <button style={{marginLeft:8, padding:'8px 12px', borderRadius:6}} onClick={async ()=>{
                  try{
                    const base = import.meta.env.VITE_API_BASE || 'http://localhost:9000'
                    await axios.post(base + '/api/firewall/unblock', { ip: summary.ip || deviceId })
                    window.dispatchEvent(new Event('se:firewall-changed'))
                    setBlocked(false)
                    setUndoVisible(false)
                    if(undoTimerRef.current) { clearTimeout(undoTimerRef.current); undoTimerRef.current = null }
                    window.dispatchEvent(new CustomEvent('se:toast', { detail: { type:'success', message: `Unblock requested for ${summary.ip || deviceId}` } }))
                  }catch(e){ window.dispatchEvent(new CustomEvent('se:toast', { detail: { type:'error', message: 'Unblock failed' } })) }
                }}>Undo</button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
