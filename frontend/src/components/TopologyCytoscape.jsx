import React, { useState, useEffect } from 'react'

export default function TopologyCytoscape({ elements, stylesheet, onReady, wheelSensitivity }){
  const [CytoscapeComponent, setCytoscapeComponent] = useState(null)

  useEffect(()=>{
    let mounted = true
    import('react-cytoscapejs').then(mod=>{ if(mounted) setCytoscapeComponent(()=>mod.default || mod) }).catch(()=>{})
    return ()=>{ mounted = false }
  },[])

  if(!CytoscapeComponent){
    return <div style={{width:'100%',height:'100%',display:'flex',alignItems:'center',justifyContent:'center'}}>Loading topology…</div>
  }

  return (
    <CytoscapeComponent
      elements={elements}
      stylesheet={stylesheet}
      style={{ width: '100%', height: '100%' }}
      cy={(cy)=>{ onReady?.(cy) }}
      wheelSensitivity={wheelSensitivity}
    />
  )
}
