import React, { useEffect, useMemo, useRef, lazy, Suspense } from 'react'
const TopologyCytoscape = lazy(() => import('./TopologyCytoscape'))

const COLORS = {
  normal: '#22c55e',
  medium: '#3b82f6',
  high: '#f59e0b',
  critical: '#ef4444',
  blocked: '#991b1b',
  sensor: '#a855f7',
  edge: '#ffffff22'
}

function severityFromRisk(risk){
  const score = Number(risk || 0)
  if(score >= 75) return 'critical'
  if(score >= 50) return 'high'
  if(score >= 25) return 'medium'
  return 'normal'
}

function iconFor(type){
  if(type === 'external') return '🌐'
  if(type === 'gateway') return '◆'
  if(type === 'sensor') return '◉'
  if(type === 'server') return '▣'
  return '●'
}

function isBlockedDevice(device, rules){
  return Array.isArray(rules) && rules.some(rule=>{
    const ip = rule.ip || rule.target
    return ip && (ip === device.ip || ip === device.id || ip === device.hostname)
  })
}

function isBlockedFlow(flow, rules){
  return Array.isArray(rules) && rules.some(rule=>{
    const ip = rule.ip || rule.target
    return ip && (ip === flow.src || ip === flow.dst)
  })
}

export default function Topology({ devices = [], flows = [], firewallRules = [], onSelectDevice, onMount }){
  const cyRef = useRef(null)
  const wrapRef = useRef(null)
  const canvasRef = useRef(null)
  const animationRef = useRef(null)
  const particlesRef = useRef([])
  const blockedEdgesRef = useRef([])

  const elements = useMemo(()=>{
    const nodes = []
    const nodeIds = new Set()
    const addNode = (device)=>{
      if(!device?.id || nodeIds.has(device.id)) return
      nodeIds.add(device.id)
      const blocked = isBlockedDevice(device, firewallRules)
      const severity = blocked ? 'blocked' : severityFromRisk(device.risk)
      nodes.push({
        data: {
          id: device.id,
          label: `${iconFor(device.type)} ${device.hostname || device.ip || device.id}`,
          risk: device.risk || 0,
          type: device.type,
          severity,
          blocked
        },
        classes: `${severity} ${device.type || ''} ${blocked ? 'blocked' : ''}`
      })
    }

    devices.forEach(addNode)
    flows.forEach(flow=>{
      if(flow.src && !nodeIds.has(flow.src)) addNode({ id: flow.src, ip: flow.src, hostname: flow.src, type: flow.src.startsWith?.('192.168.') ? 'workstation' : 'external', risk: flow.risk || 0 })
      if(flow.dst && !nodeIds.has(flow.dst)) addNode({ id: flow.dst, ip: flow.dst, hostname: flow.dst, type: flow.dst.startsWith?.('192.168.') ? 'workstation' : 'external', risk: Math.max(0, Number(flow.risk || 0) - 10) })
    })

    const edges = flows.slice(-180).map((flow, i)=>{
      const blocked = isBlockedFlow(flow, firewallRules)
      const severity = blocked ? 'blocked' : severityFromRisk(flow.risk)
      return {
        data: {
          id: flow.id || `edge-${i}`,
          source: flow.src,
          target: flow.dst,
          risk: flow.risk || 0,
          packets: flow.packets || 1,
          severity,
          blocked,
          drift: flow.drift
        },
        classes: `${severity} ${blocked ? 'blocked' : ''} ${flow.drift ? 'drift' : ''}`
      }
    }).filter(edge=>edge.data.source && edge.data.target && edge.data.source !== edge.data.target)

    return [...nodes, ...edges]
  }, [devices, flows, firewallRules])

  useEffect(()=>{
    const cy = cyRef.current
    if(!cy) return

    cy.removeAllListeners()
    cy.on('tap', 'node', evt=>onSelectDevice?.(evt.target.id()))
    cy.on('cxttap', 'node', evt=>onSelectDevice?.(evt.target.id()))
    cy.on('dbltap', 'edge', evt=>{
      const edge = evt.target
      window.dispatchEvent(new CustomEvent('se:toast', { detail: { type: 'info', message: `Flow ${edge.source().id()} -> ${edge.target().id()} · risk ${edge.data('risk') || 0}` } }))
    })

    const gateway = cy.nodes('[type = "gateway"]')
    const externals = cy.nodes('[type = "external"]')
    const sensors = cy.nodes('[type = "sensor"]')
    try{
      gateway.positions((node, i)=>({ x: 230, y: 150 + i * 70 }))
      externals.positions((node, i)=>({ x: 40, y: 90 + i * 90 }))
      sensors.positions((node, i)=>({ x: 430, y: 90 + i * 100 }))
      cy.layout({
        name: 'cose',
        animate: true,
        animationDuration: 350,
        nodeRepulsion: 9000,
        idealEdgeLength: 120,
        padding: 30
      }).run()
      setTimeout(()=>cy.fit(undefined, 35), 420)
    }catch(e){}

    const api = {
      zoomToDevice: (id)=>{
        const node = cy.getElementById(id)
        if(node?.length){
          node.select()
          cy.animate({ fit: { eles: node, padding: 90 }, duration: 450 })
        }
      },
      fit: ()=>cy.fit(undefined, 35),
      exportSnapshot: async ()=>cy.png({ full: true, bg: '#0a0e1a', scale: 2 })
    }
    onMount?.(api)
  }, [elements, onMount, onSelectDevice])

  useEffect(()=>{
    const cy = cyRef.current
    const canvas = canvasRef.current
    const wrap = wrapRef.current
    if(!cy || !canvas || !wrap) return
    const ctx = canvas.getContext('2d')

    const resize = ()=>{
      const rect = wrap.getBoundingClientRect()
      canvas.width = rect.width * window.devicePixelRatio
      canvas.height = rect.height * window.devicePixelRatio
      canvas.style.width = `${rect.width}px`
      canvas.style.height = `${rect.height}px`
      ctx.setTransform(window.devicePixelRatio, 0, 0, window.devicePixelRatio, 0, 0)
    }

    const rebuildParticles = ()=>{
      const particles = []
      const blockedEdges = []
      cy.edges().forEach((edge)=>{
        const source = edge.source()
        const target = edge.target()
        if(!source.length || !target.length) return
        const src = source.renderedPosition()
        const dst = target.renderedPosition()
        const risk = Number(edge.data('risk') || 0)
        const severity = edge.data('severity') || severityFromRisk(risk)
        const color = COLORS[severity] || COLORS.normal
        const blocked = Boolean(edge.data('blocked'))
        const count = Math.min(5, Math.max(1, Math.ceil(Number(edge.data('packets') || 1) / 80)))
        for(let i = 0; i < count; i += 1){
          particles.push({
            src,
            dst,
            risk,
            blocked,
            color,
            t: Math.random(),
            speed: 0.004 + Math.min(0.018, risk / 5000)
          })
        }
        if(blocked) blockedEdges.push({ src, dst })
      })
      particlesRef.current = particles.slice(0, 260)
      blockedEdgesRef.current = blockedEdges
    }

    const draw = ()=>{
      const rect = wrap.getBoundingClientRect()
      ctx.clearRect(0, 0, rect.width, rect.height)
      ctx.fillStyle = 'rgba(10, 14, 26, 0.2)'
      ctx.fillRect(0, 0, rect.width, rect.height)

      particlesRef.current.forEach(p=>{
        const maxT = p.blocked ? 0.5 : 1
        p.t += p.speed
        if(p.t > maxT) p.t = 0
        const x = p.src.x + (p.dst.x - p.src.x) * p.t
        const y = p.src.y + (p.dst.y - p.src.y) * p.t
        const radius = p.risk >= 75 ? 4.5 : p.risk >= 50 ? 3.5 : 2.4
        const trail = p.risk >= 50 ? 4 : 2
        for(let i = trail; i >= 0; i -= 1){
          const tx = x - (p.dst.x - p.src.x) * 0.012 * i
          const ty = y - (p.dst.y - p.src.y) * 0.012 * i
          ctx.globalAlpha = 0.14 + (trail - i) * 0.12
          ctx.beginPath()
          ctx.fillStyle = p.color
          ctx.arc(tx, ty, Math.max(1, radius - i * 0.45), 0, Math.PI * 2)
          ctx.fill()
        }
        if(p.blocked && p.t > 0.47){
          ctx.globalAlpha = 0.6
          ctx.strokeStyle = COLORS.blocked
          ctx.lineWidth = 2
          ctx.beginPath()
          ctx.arc(x, y, 10 + Math.sin(Date.now() / 120) * 2, 0, Math.PI * 2)
          ctx.stroke()
        }
      })

      blockedEdgesRef.current.forEach(edge=>{
        const x = (edge.src.x + edge.dst.x) / 2
        const y = (edge.src.y + edge.dst.y) / 2
        ctx.globalAlpha = 0.95
        ctx.fillStyle = COLORS.blocked
        ctx.beginPath()
        ctx.arc(x, y, 11, 0, Math.PI * 2)
        ctx.fill()
        ctx.strokeStyle = '#fee2e2'
        ctx.lineWidth = 2
        ctx.beginPath()
        ctx.moveTo(x - 6, y + 6)
        ctx.lineTo(x + 6, y - 6)
        ctx.stroke()
      })

      ctx.globalAlpha = 1
      animationRef.current = requestAnimationFrame(draw)
    }

    resize()
    rebuildParticles()
    const update = ()=>rebuildParticles()
    cy.on('position zoom pan render', update)
    window.addEventListener('resize', resize)
    animationRef.current = requestAnimationFrame(draw)

    return ()=>{
      if(animationRef.current) cancelAnimationFrame(animationRef.current)
      cy.removeListener('position zoom pan render', update)
      window.removeEventListener('resize', resize)
    }
  }, [elements])

  const stylesheet = [
    {
      selector: 'node',
      style: {
        label: 'data(label)',
        color: '#dbeafe',
        'font-size': 10,
        'text-valign': 'bottom',
        'text-margin-y': 9,
        'background-color': '#111827',
        'border-width': 2,
        'border-color': '#22c55e',
        width: 'mapData(risk, 0, 100, 34, 58)',
        height: 'mapData(risk, 0, 100, 34, 58)',
        'transition-property': 'background-color, border-color, width, height',
        'transition-duration': '220ms',
        'overlay-opacity': 0
      }
    },
    { selector: 'node.normal', style: { 'border-color': COLORS.normal, 'background-color': '#11241c' } },
    { selector: 'node.medium', style: { 'border-color': COLORS.medium, 'background-color': '#10203d' } },
    { selector: 'node.high', style: { 'border-color': COLORS.high, 'background-color': '#2d2110' } },
    { selector: 'node.critical', style: { 'border-color': COLORS.critical, 'background-color': '#301417', 'border-width': 4 } },
    { selector: 'node.blocked', style: { 'border-color': COLORS.blocked, 'background-color': '#3a1114', 'border-width': 5, 'border-style': 'dashed' } },
    { selector: 'node.sensor', style: { 'border-color': COLORS.sensor, 'background-color': '#24133d', shape: 'hexagon' } },
    { selector: 'node.gateway', style: { shape: 'diamond' } },
    { selector: 'node.external', style: { shape: 'round-rectangle', 'border-color': '#94a3b8', 'background-color': '#1e293b' } },
    { selector: 'node:selected', style: { 'border-color': '#00d4ff', 'border-width': 6 } },
    {
      selector: 'edge',
      style: {
        width: 1,
        'line-color': COLORS.edge,
        'curve-style': 'bezier',
        'target-arrow-shape': 'triangle',
        'target-arrow-color': COLORS.edge,
        opacity: 0.55,
        'transition-property': 'line-color, width, opacity',
        'transition-duration': '220ms'
      }
    },
    { selector: 'edge.medium', style: { 'line-color': COLORS.medium, 'target-arrow-color': COLORS.medium, width: 1.5, opacity: 0.75 } },
    { selector: 'edge.high', style: { 'line-color': COLORS.high, 'target-arrow-color': COLORS.high, width: 2, opacity: 0.85 } },
    { selector: 'edge.critical', style: { 'line-color': COLORS.critical, 'target-arrow-color': COLORS.critical, width: 2.5, opacity: 0.95 } },
    { selector: 'edge.blocked', style: { 'line-color': COLORS.blocked, 'target-arrow-color': COLORS.blocked, width: 3, 'line-style': 'dashed', opacity: 0.95 } },
    { selector: 'edge.drift', style: { 'line-style': 'dashed' } }
  ]

  return (
    <div className="topology-wrap" ref={wrapRef}>
      <Suspense fallback={<div style={{padding:16,color:'#94a3b8'}}>Loading topology core…</div>}>
        <TopologyCytoscape elements={elements} stylesheet={stylesheet} onReady={(cy)=>{ cyRef.current = cy }} wheelSensitivity={0.18} />
      </Suspense>
      <canvas ref={canvasRef} className="topology-canvas" />
      <div className="mini-map">
        <span>Topology</span>
        <i />
      </div>
    </div>
  )
}
