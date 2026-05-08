import React, { useRef, useEffect, useState } from 'react'
import CytoscapeComponent from 'react-cytoscapejs'

export default function Topology({devices, flows, alerts, firewallRules = [], onSelectDevice, onMount}){
  const cyRef = useRef(null)
  const containerRef = useRef(null)
  const canvasRef = useRef(null)
  const [particles, setParticles] = useState([])
  const [demoPulseAt, setDemoPulseAt] = useState(0)

  const elements = []
  // devices expected as dict or list
  const devList = Array.isArray(devices) ? devices : (devices && devices.profiles ? devices.profiles : [])

  devList.forEach((d, idx)=>{
    const id = d.mac || d.id || ('dev'+idx)
    const risk = d.risk || d.score || 0
    const color = risk >= 75 ? '#b00020' : risk >=50 ? '#ff6f00' : risk >=25 ? '#ffd600' : '#4caf50'
    // if device is blocked, add a distinct border
    const isBlocked = Array.isArray(firewallRules) && firewallRules.find(r=>r.ip===d.ip||r.ip===d.host||r.ip===d.mac)
    const style = isBlocked ? { 'background-color': color, 'border-width': 4, 'border-color': '#E74C3C' } : { 'background-color': color }
    elements.push({ data: { id, label: d.name||d.host||id }, style })
  })

  // flows: try to map flows edges
    if (flows && Array.isArray(flows.flows || flows)){
    const fs = flows.flows || flows
    fs.forEach((f, i)=>{
      const src = f.src_mac || f.src || f.src_ip || f.src_host
      const dst = f.dst_mac || f.dst || f.dst_ip || f.dst_host
      if(src && dst){
        const edgeId = `e${i}`
        // determine if this flow is blocked or high-risk
        const isBlocked = (f.risk && f.risk>=75) || (Array.isArray(firewallRules) && firewallRules.find(r=>r.ip===f.src_ip||r.ip===f.dst_ip||r.ip===f.src_mac||r.ip===f.dst_mac))
        const edgeStyle = isBlocked ? { 'line-color': '#E74C3C', 'line-style':'dashed', 'width': 3, 'opacity': 0.9 } : { 'line-color': '#88C999', 'width': 1.6, 'opacity': 0.7 }
        elements.push({ data: { id: edgeId, source: src, target: dst, label: f.packets || '' }, style: edgeStyle })
      }
    })
  }
  useEffect(()=>{
    if(!cyRef.current) return
    const cy = cyRef.current
    cy.layout({ name: 'cose' }).run()
    cy.fit()

    // node click handler -> call onSelectDevice
    if(typeof onSelectDevice === 'function'){
      cy.on('tap', 'node', (evt)=>{
        const node = evt.target
        const id = node.data('id')
        onSelectDevice(id)
      })
    }

    // build particles from flows
    const ps = []
    try{
      const fs = flows && (Array.isArray(flows.flows || flows) ? (flows.flows || flows) : [])
      fs.forEach((f,i)=>{
        const srcId = f.src_mac || f.src || f.src_ip || f.src_host
        const dstId = f.dst_mac || f.dst || f.dst_ip || f.dst_host
        const srcNode = cy.getElementById(srcId)
        const dstNode = cy.getElementById(dstId)
        if(srcNode && dstNode && srcNode.length && dstNode.length){
          const srcPos = srcNode.renderedPosition()
          const dstPos = dstNode.renderedPosition()
          const speed = Math.min(3 + (f.packets||0)/50, 12)
          const color = (f.risk>=75) ? '#E74C3C' : (f.risk>=50 ? '#F1C40F' : '#27AE60')
          // spawn a few particles per flow proportional to intensity
          const count = Math.min(1 + Math.floor((f.packets||0)/80), 8)
          for(let k=0;k<count;k++){
            // add slight jitter for natural motion
            const jitter = (Math.random()-0.5)*6
            ps.push({ x0: srcPos.x + jitter, y0: srcPos.y + jitter, x1: dstPos.x + jitter, y1: dstPos.y + jitter, t: Math.random(), speed, color })
          }
        }
      })
    }catch(e){ console.warn('particle build', e) }
    setParticles(ps)

    // expose helper API
    if(typeof onMount === 'function'){
      const api = {
        zoomToDevice: (id)=>{
          try{
            const node = cy.getElementById(id)
            if(node && node.length){
              cy.animate({ fit: { eles: node, padding: 40 }, duration: 400 })
            }
          }catch(e){}
        },
        exportSnapshot: async ()=>{
          try{
            const cyPng = cy.png({ full: true })
            const overlay = canvasRef.current
            const w = overlay.width, h = overlay.height
            const off = document.createElement('canvas')
            off.width = w; off.height = h
            const ctx = off.getContext('2d')
            const base = new Image()
            base.src = cyPng
            await new Promise(r=> base.onload = r)
            ctx.drawImage(base, 0, 0, w, h)
            const ov = new Image()
            ov.src = overlay.toDataURL()
            await new Promise(r=> ov.onload = r)
            ctx.drawImage(ov, 0, 0, w, h)
            // draw legend in bottom-right corner to match UI
            const legendW = 180
            const legendH = 120
            const pad = 12
            ctx.fillStyle = 'rgba(7,16,24,0.95)'
            ctx.fillRect(w-legendW-pad, pad, legendW, legendH)
            ctx.fillStyle = '#E6EEF6'
            ctx.font = '600 14px Inter, Arial'
            ctx.fillText('Risk Legend', w-legendW+8-pad, 28)
            const items = [ ['CRITICAL','#FF3B30'], ['HIGH','#FF9500'], ['MEDIUM','#FFD60A'], ['LOW','#34C759'], ['NORMAL','#8E8E93'], ['BLOCKED','#E74C3C'] ]
            ctx.font = '12px Inter, Arial'
            items.forEach((it, idx)=>{
              const y = 48 + idx*18
              ctx.fillStyle = it[1]
              ctx.fillRect(w-legendW+8-pad, y-10, 12, 12)
              ctx.fillStyle = '#C9D6E3'
              ctx.fillText(it[0], w-legendW+28-pad, y)
            })
            return off.toDataURL('image/png')
          }catch(e){ console.warn('snapshot failed', e); return null }
        }
      }
      try{ onMount(api) }catch(e){}
    }

    // animation loop
    let raf = null
    const canvas = canvasRef.current
    const ctx = canvas && canvas.getContext && canvas.getContext('2d')
    const resize = ()=>{
      if(!containerRef.current || !canvas) return
      const r = containerRef.current.getBoundingClientRect()
      canvas.width = r.width
      canvas.height = r.height
      canvas.style.width = r.width + 'px'
      canvas.style.height = r.height + 'px'
    }
    resize()

    const blockedEdges = []
    try{
      const fs = flows && (Array.isArray(flows.flows || flows) ? (flows.flows || flows) : [])
      fs.forEach((f,i)=>{
        const srcId = f.src_mac || f.src || f.src_ip || f.src_host
        const dstId = f.dst_mac || f.dst || f.dst_ip || f.dst_host
        const srcNode = cy.getElementById(srcId)
        const dstNode = cy.getElementById(dstId)
        if(srcNode && dstNode && srcNode.length && dstNode.length){
          const srcPos = srcNode.renderedPosition()
          const dstPos = dstNode.renderedPosition()
          const speed = Math.min(3 + (f.packets||0)/50, 12)
          const color = (f.risk>=75) ? '#E74C3C' : (f.risk>=50 ? '#F1C40F' : '#27AE60')
          const count = Math.min(1 + Math.floor((f.packets||0)/80), 8)
          for(let k=0;k<count;k++){
            const jitter = (Math.random()-0.5)*6
            ps.push({ x0: srcPos.x + jitter, y0: srcPos.y + jitter, x1: dstPos.x + jitter, y1: dstPos.y + jitter, t: Math.random(), speed, color })
          }
          // mark blocked/high risk edge for overlay icon drawing
          const isBlocked = (f.risk && f.risk>=75) || (Array.isArray(firewallRules) && firewallRules.find(r=>r.ip===f.src_ip||r.ip===f.dst_ip||r.ip===f.src_mac||r.ip===f.dst_mac))
          if(isBlocked){
            blockedEdges.push({ x0: srcPos.x, y0: srcPos.y, x1: dstPos.x, y1: dstPos.y })
          }
        }
      })
    }catch(e){ console.warn('particle build', e) }
    setParticles(ps)

    // animation loop
    const loop = ()=>{
      if(!ctx) return
      // draw translucent background for motion blur effect
      ctx.fillStyle = 'rgba(7,16,24,0.18)'
      ctx.fillRect(0,0,canvas.width,canvas.height)
      particles.forEach(p=>{
        p.t += (p.speed/80)
        if(p.t>1) p.t = 0
        const x = p.x0 + (p.x1-p.x0)*p.t
        const y = p.y0 + (p.y1-p.y0)*p.t
        // draw particle with trailing effect
        for(let s=0;s<5;s++){
          const alpha = 0.28 * (1 - s/5)
          ctx.beginPath()
          ctx.fillStyle = p.color
          ctx.globalAlpha = alpha
          const sx = x - s* (p.x1-p.x0)*0.006
          const sy = y - s* (p.y1-p.y0)*0.006
          ctx.arc(sx, sy, 3 - s*0.5, 0, Math.PI*2)
          ctx.fill()
        }
      })

      // draw blocked icons at midpoints
      blockedEdges.forEach(e=>{
        const mx = (e.x0+e.x1)/2
        const my = (e.y0+e.y1)/2
        // draw stop circle
        ctx.beginPath()
        ctx.fillStyle = '#E74C3C'
        ctx.globalAlpha = 0.95
        ctx.arc(mx, my, 10, 0, Math.PI*2)
        ctx.fill()
        // draw white bar
        ctx.beginPath()
        ctx.fillStyle = '#fff'
        ctx.rect(mx-6, my-3, 12, 6)
        ctx.fill()
      })

      // demo pulse overlay (temporary visual emphasis)
      const now = Date.now()/1000
      if(demoPulseAt && now - demoPulseAt < 6){
        const prog = (now - demoPulseAt) / 6
        const alpha = 0.9 * (1 - prog)
        ctx.beginPath()
        ctx.fillStyle = '#E74C3C'
        ctx.globalAlpha = alpha * 0.25
        ctx.fillRect(0,0,canvas.width,canvas.height)
      }

      raf = requestAnimationFrame(loop)
    }
    raf = requestAnimationFrame(loop)

    const onDemo = (e)=>{
      setDemoPulseAt(Date.now()/1000)
    }
    window.addEventListener('se:demo-started', onDemo)
    window.addEventListener('resize', resize)
    return ()=>{ if(raf) cancelAnimationFrame(raf); window.removeEventListener('resize', resize) }
  },[devices,flows,onSelectDevice])

  return (
    <div ref={containerRef} style={{position:'relative',height:600, border:'1px solid #eee', borderRadius:6}}>
      <CytoscapeComponent
        elements={elements}
        style={{ width: '100%', height: '100%' }}
        cy={(cy)=>{ cyRef.current = cy; cy.layout({ name: 'cose' }).run() }}
      />
      <canvas ref={canvasRef} style={{position:'absolute', left:0, top:0, pointerEvents:'none'}} />
    </div>
  )
}
