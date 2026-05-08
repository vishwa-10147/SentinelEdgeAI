import React, { useEffect, useState } from 'react'
import axios from 'axios'
import Topology from './components/Topology'
import DeviceDetail from './components/DeviceDetail'
import Legend from './components/Legend'
import FirewallActivity from './components/FirewallActivity'
import PresenterMode from './components/PresenterMode'

// lightweight toast/modal system via window events

export default function App(){
  const [devices, setDevices] = useState([])
  const [flows, setFlows] = useState([])
  const [alerts, setAlerts] = useState([])
  const [firewallRules, setFirewallRules] = useState([])
  const [health, setHealth] = useState({})

  useEffect(()=>{
    const base = import.meta.env.VITE_API_BASE || 'http://localhost:9000'
    const fetch = async ()=>{
      try{
        const [d,f,a,fw,h] = await Promise.all([
          axios.get(base + '/api/device_profiles'),
          axios.get(base + '/api/live_stats'),
          axios.get(base + '/api/alerts'),
          axios.get(base + '/api/firewall/rules').catch(()=>({data:[]})),
          axios.get(base + '/api/health').catch(()=>({data:{}}))
        ])
        setDevices(d.data || [])
        setFlows(f.data || [])
        setAlerts(a.data || [])
        setFirewallRules((fw && fw.data) || [])
        setHealth((h && h.data) || {})
      }catch(e){
        console.error('fetch error', e)
      }
    }
    fetch()
    const onFwChange = ()=> fetch()
    window.addEventListener('se:firewall-changed', onFwChange)
    const t = setInterval(fetch, 5000)
    return ()=>clearInterval(t)
  },[])

  // timeline control
  const [playback, setPlayback] = useState(true)
  const [timeWindow, setTimeWindow] = useState(60)

  const [selected, setSelected] = useState(null)
  const [topologyApi, setTopologyApi] = useState(null)
  const [toasts, setToasts] = useState([])
  const [modal, setModal] = useState(null)

  useEffect(()=>{
    const onToast = (e)=>{
      const id = Math.random().toString(36).slice(2,9)
      const t = { id, ...e.detail }
      setToasts(s=>[t,...s])
      setTimeout(()=> setToasts(s=>s.filter(x=>x.id!==id)), 6000)
    }
    const onModal = (e)=> setModal(e.detail)
    window.addEventListener('se:toast', onToast)
    window.addEventListener('se:modal', onModal)
    return ()=>{ window.removeEventListener('se:toast', onToast); window.removeEventListener('se:modal', onModal) }
  },[])

  const emitModalResult = (ok, payload)=>{
    window.dispatchEvent(new CustomEvent('se:modal-result', { detail: { ok, payload } }))
    setModal(null)
  }

  return (
    <div style={{padding:20,fontFamily:'Inter, Arial'}}>
      <h1>SentinelEdgeAI — Topology</h1>
      <div style={{display:'flex', gap:12, marginBottom:12}}>
        <div style={{background:'#071018', color:'#fff', padding:12, borderRadius:8}}>
          <div style={{fontSize:12,color:'#AAB2BD'}}>Traffic Volume</div>
          <div style={{fontSize:20,fontWeight:700}}>{flows && flows.summary && flows.summary.total_bytes ? Math.round(flows.summary.total_bytes/1024) + ' KB/s' : '—'}</div>
        </div>
        <div style={{background:'#071018', color:'#fff', padding:12, borderRadius:8}}>
          <div style={{fontSize:12,color:'#AAB2BD'}}>Active Devices</div>
          <div style={{fontSize:20,fontWeight:700}}>{Array.isArray(devices)?devices.length: (devices && devices.profiles?devices.profiles.length:0)}</div>
        </div>
        <div style={{background:'#071018', color:'#fff', padding:12, borderRadius:8}}>
          <div style={{fontSize:12,color:'#AAB2BD'}}>Blocked</div>
          <div style={{fontSize:20,fontWeight:700}}>{Array.isArray(firewallRules)?firewallRules.length:0}</div>
        </div>
        <div style={{marginLeft:'auto', background:'#071018', color:'#fff', padding:12, borderRadius:8}}>
          <div style={{fontSize:12,color:'#AAB2BD'}}>System Health</div>
          <div style={{fontSize:14}}>{health && health.pi && `Pi CPU ${health.pi.cpu || '?'}%`}</div>
        </div>
          <div style={{marginLeft:8}}>
          <button onClick={async ()=>{
            const base = import.meta.env.VITE_API_BASE || 'http://localhost:9000'
            try{
              window.dispatchEvent(new CustomEvent('se:toast', { detail: { type:'info', message: 'Starting demo attack...' } }))
              const res = await axios.post(base + '/api/demo/run', { simulate_type: 'portscan' })
              window.dispatchEvent(new CustomEvent('se:toast', { detail: { type:'success', message: 'Demo started' } }))
              // notify topology + other components
              window.dispatchEvent(new CustomEvent('se:demo-started', { detail: { pid: res.data.pid } }))
            }catch(e){ window.dispatchEvent(new CustomEvent('se:toast', { detail: { type:'error', message: 'Demo failed to start' } })) }
          }} style={{padding:'8px 12px', borderRadius:6}}>Simulate Attack</button>
          <button onClick={async ()=>{
            const base = import.meta.env.VITE_API_BASE || 'http://localhost:9000'
            try{
              window.dispatchEvent(new CustomEvent('se:toast', { detail: { type:'info', message: 'Starting presenter demo...' } }))
              await axios.post(base + '/api/demo/presenter', { simulate_type: 'portscan' })
              window.dispatchEvent(new CustomEvent('se:toast', { detail: { type:'success', message: 'Presenter demo started' } }))
            }catch(e){ window.dispatchEvent(new CustomEvent('se:toast', { detail: { type:'error', message: 'Presenter demo failed' } })) }
          }} style={{marginLeft:8,padding:'8px 12px', borderRadius:6}}>Start Presenter Demo</button>
        </div>
      </div>
      <div style={{display:'flex',gap:20}}>
        <div style={{flex:2}}>
          <Topology devices={devices} flows={flows} alerts={alerts} firewallRules={firewallRules} onSelectDevice={setSelected} onMount={(api)=>setTopologyApi(api)} />
        </div>
        <div style={{flex:1}}>
          <h2>Alerts</h2>
          <ul>
            {Array.isArray(alerts) ? alerts.slice(-20).reverse().map((al,i)=> (
              <li key={i}><b>{al.device||al.src||'unknown'}</b>: {al.summary||al.reason||JSON.stringify(al)}</li>
            )) : <li>No alerts</li>}
          </ul>
          <div style={{marginTop:12}}>
            <FirewallActivity />
          </div>
        </div>
      </div>
      <Legend />
      <div style={{position:'fixed', left:20, bottom:24, width:400, background:'#071018', padding:10, borderRadius:8}}>
        <div style={{display:'flex', alignItems:'center', gap:8}}>
          <button onClick={()=>setPlayback(p=>!p)} style={{padding:'6px 10px'}}>{playback ? 'Pause' : 'Play'}</button>
          <label style={{color:'#AAB2BD'}}>Window:</label>
          <input type="range" min={10} max={600} value={timeWindow} onChange={e=>setTimeWindow(Number(e.target.value))} />
          <div style={{color:'#AAB2BD', width:60, textAlign:'right'}}>{timeWindow}s</div>
        </div>
      </div>
      {selected && <DeviceDetail deviceId={selected} onClose={()=>setSelected(null)} topologyApi={topologyApi} />}

      {/* Modal */}
      {modal && (
        <div style={{position:'fixed', left:0, top:0,right:0,bottom:0, display:'flex', alignItems:'center', justifyContent:'center', background:'rgba(0,0,0,0.5)'}}>
          <div style={{background:'#fff', color:'#000', padding:20, borderRadius:8, width:420}}>
            <h3 style={{marginTop:0}}>{modal.title||'Confirm'}</h3>
            <div style={{marginTop:8, marginBottom:16}}>{modal.message}</div>
            <div style={{textAlign:'right'}}>
              <button onClick={()=>emitModalResult(false,null)} style={{marginRight:8}}>Cancel</button>
              <button onClick={()=>emitModalResult(true, modal.payload)} style={{background:'#E74C3C', color:'#fff', padding:'6px 10px', borderRadius:6}}>Confirm</button>
            </div>
          </div>
        </div>
      )}

      {/* Toasts */}
      <div style={{position:'fixed', right:20, bottom:20, display:'flex', flexDirection:'column', gap:8}}>
        {toasts.map(t=> (
          <div key={t.id} style={{background: t.type==='error'? '#E74C3C': t.type==='success'? '#27AE60': '#333', color:'#fff', padding:10, borderRadius:6, minWidth:200}}>{t.message}</div>
        ))}
      </div>
      <PresenterMode />
    </div>
  )
}
