import React, { useEffect, useState } from 'react'
import { apiGet, apiPost } from '../api'

export default function FirewallActivity(){
  const [actions, setActions] = useState([])

  const fetch = async ()=>{
    setActions(await apiGet('/api/firewall/actions', []))
  }
  useEffect(()=>{ fetch(); const t = setInterval(fetch,5000); const onFw = ()=>fetch(); window.addEventListener('se:firewall-changed', onFw); return ()=>{ clearInterval(t); window.removeEventListener('se:firewall-changed', onFw) } }, [])

  const undo = async (ip, id)=>{
    try{
      await apiPost('/api/firewall/unblock', { ip })
      window.dispatchEvent(new Event('se:firewall-changed'))
      // show toast
      window.dispatchEvent(new CustomEvent('se:toast', { detail: { type:'success', message: `Unblock requested for ${ip}` } }))
      fetch()
    }catch(e){ window.dispatchEvent(new CustomEvent('se:toast', { detail: { type:'error', message: `Unblock failed for ${ip}` } })) }
  }

  return (
    <div style={{background:'#071018', color:'#fff', padding:12, borderRadius:8}}>
      <h3>Firewall Activity</h3>
      <div style={{maxHeight:300, overflow:'auto'}}>
        <table style={{width:'100%', borderCollapse:'collapse'}}>
          <thead><tr style={{textAlign:'left'}}><th>Time</th><th>IP</th><th>Action</th><th>TTL</th><th>Status</th><th></th></tr></thead>
          <tbody>
            {actions.slice().reverse().map((it, idx)=> (
              <tr key={idx} style={{borderTop:'1px solid rgba(255,255,255,0.03)'}}>
                <td style={{fontSize:12}}>{it.timestamp || ''}</td>
                <td style={{fontSize:12}}>{it.ip || it.target || ''}</td>
                <td style={{fontSize:12}}>{it.action||''}</td>
                <td style={{fontSize:12}}>{it.ttl? it.ttl+'s' : '-'}</td>
                <td style={{fontSize:12}}>{it.status || (it.action==='block'? 'active':'-')}</td>
                <td style={{textAlign:'right'}}>{it.action==='block' && it.status==='active' && <button onClick={()=>undo(it.ip||it.target)} style={{padding:'6px 8px'}}>Undo</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
