// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React, { useCallback, useEffect, useMemo, useState, useRef } from 'react'
import type { ParsedPolicy } from '../policy/types'
import ServiceBadge from './ServiceBadge'

interface Node {
  id: string
  type: 'policy' | 'statement' | 'item'
  data: Record<string, unknown>
  position: { x: number; y: number }
}

interface Edge {
  id: string
  source: string
  target: string
}

const BADGE_KINDS = ['Action', 'NotAction', 'Resource', 'NotResource']

const NODE_WIDTH = 340
const NODE_HEIGHT = 80
const FIT_MARGIN = 24
// Fit never zooms out past this, so text stays readable; taller graphs fit the width.
const MIN_FIT_ZOOM = 0.75
// Room for the zoom controls: 10px inset + 32px buttons + 10px gap.
const CONTROLS_GUTTER = 52
const DRAG_THRESHOLD = 3

function graphBounds(nodes: Node[]) {
  if (!nodes.length) return null
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity
  for (const n of nodes) {
    minX = Math.min(minX, n.position.x)
    minY = Math.min(minY, n.position.y)
    maxX = Math.max(maxX, n.position.x + NODE_WIDTH)
    maxY = Math.max(maxY, n.position.y + NODE_HEIGHT)
  }
  return { minX, minY, width: maxX - minX, height: maxY - minY }
}

function ellipsizeMiddle(str: string, max = 36) {
  if (!str) return ''
  if (str.length <= max) return str
  const half = Math.floor((max - 1) / 2)
  return `${str.slice(0, half)}…${str.slice(-half)}`
}

function layout(nodes: Node[], edges: Edge[]) {
  const levels: { [key: number]: Node[] } = {}
  const nodeMap: { [key: string]: Node } = {}
  
  nodes.forEach(node => {
    nodeMap[node.id] = node
    const level = node.type === 'policy' ? 0 : node.type === 'statement' ? 1 : 2
    if (!levels[level]) levels[level] = []
    levels[level].push(node)
  })

  Object.keys(levels).forEach(levelKey => {
    const level = parseInt(levelKey)
    const levelNodes = levels[level]
    
    let spacing: number
    
    if (level === 1) {
      const statementNodes = levelNodes
      const childNodes = levels[2] || []
      
      const avgChildrenPerStatement = childNodes.length / Math.max(statementNodes.length, 1)
      
      if (statementNodes.length <= 2) {
        if (avgChildrenPerStatement > 6) {
          spacing = NODE_HEIGHT + 180
        } else if (avgChildrenPerStatement > 3) {
          spacing = NODE_HEIGHT + 150
        } else {
          spacing = NODE_HEIGHT + 120
        }
      } else if (statementNodes.length <= 4) {
        if (avgChildrenPerStatement > 4) {
          spacing = NODE_HEIGHT + 100
        } else {
          spacing = NODE_HEIGHT + 80
        }
      } else if (statementNodes.length <= 6) {
        spacing = NODE_HEIGHT + 60
      } else {
        spacing = NODE_HEIGHT + 40
      }
    } else {
      if (levelNodes.length <= 2) {
        spacing = NODE_HEIGHT + 100
      } else if (levelNodes.length <= 4) {
        spacing = NODE_HEIGHT + 60
      } else if (levelNodes.length <= 6) {
        spacing = NODE_HEIGHT + 32
      } else {
        spacing = NODE_HEIGHT + 12
      }
    }
    
    const totalHeight = (levelNodes.length - 1) * spacing
    const startY = 300 - totalHeight / 2

    levelNodes.forEach((node, index) => {
      node.position = {
        x: level * (NODE_WIDTH + 120) + 100,
        y: startY + index * spacing
      }
    })
  })

  return { nodes, edges }
}

export default function Graph({ parsed, collapsed, onToggleStatement }: { parsed: ParsedPolicy | null, collapsed: Record<string, boolean>, onToggleStatement: (id: string) => void }) {
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [isDragging, setIsDragging] = useState(false)
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 })
  // A drag that ends on a statement node must not toggle it.
  const downPos = useRef({ x: 0, y: 0 })
  const dragged = useRef(false)
  const svgRef = useRef<SVGSVGElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const fittedPolicy = useRef<ParsedPolicy | null>(null)

  // Returns false when the container has no size yet, so the caller can retry.
  const fitView = useCallback((ns: Node[]): boolean => {
    const el = containerRef.current
    const bounds = graphBounds(ns)
    if (!el || !bounds) return false
    const cw = el.clientWidth
    const ch = el.clientHeight
    if (!cw || !ch) return false
    const usableW = cw - CONTROLS_GUTTER - FIT_MARGIN
    const fitWidth = usableW / bounds.width
    const fitHeight = (ch - 2 * FIT_MARGIN) / bounds.height
    const panX = (z: number) =>
      CONTROLS_GUTTER + Math.max(0, (usableW - bounds.width * z) / 2) - bounds.minX * z
    const scale = Math.min(fitWidth, fitHeight, 1)
    if (scale >= MIN_FIT_ZOOM) {
      setZoom(scale)
      setPan({ x: panX(scale), y: (ch - bounds.height * scale) / 2 - bounds.minY * scale })
      return true
    }
    const z = Math.max(MIN_FIT_ZOOM, Math.min(fitWidth, 1))
    setZoom(z)
    setPan({ x: panX(z), y: FIT_MARGIN - bounds.minY * z })
    return true
  }, [])

  // Derived during render, so no frame shows stale (possibly unredacted) values.
  const { nodes, edges } = useMemo(() => {
    if (!parsed) return { nodes: [] as Node[], edges: [] as Edge[] }
    const ns: Node[] = []
    const es: Edge[] = []

    ns.push({ 
      id: 'Policy', 
      type: 'policy', 
      data: { label: parsed.id, version: parsed.version }, 
      position: {x:0,y:0} 
    })

    parsed.statements.forEach((st, idx) => {
      const n = idx + 1
      ns.push({ 
        id: st.id, 
        type:'statement', 
        data: { title: `Statement ${n}: ${st.effect}`, effect: st.effect, sid: st.sid }, 
        position:{x:0,y:0}
      })
      es.push({ id: `e-Policy-${st.id}`, source: 'Policy', target: st.id })
      
      if (collapsed[st.id]) return
      
      const items: {id:string, kind:string, value:string, tip:string, subtext?:string}[] = []
      // Not* elements mean "everything except these", so label them distinctly.
      const actionKind = st.notAction ? 'NotAction' : 'Action'
      const resourceKind = st.notResource ? 'NotResource' : 'Resource'
      const principalKind = st.notPrincipal ? 'NotPrincipal' : 'Principal'
      const except = (kind: string) => kind.startsWith('Not') ? ' (everything except this)' : ''
      st.actions.forEach((a,i)=> items.push({id:`${st.id}-A${i}`, kind:actionKind, value:a, tip:`${actionKind} ${a}${except(actionKind)}`}))
      st.resources.forEach((r,i)=> items.push({id:`${st.id}-R${i}`, kind:resourceKind, value:r, tip:`${resourceKind} ${r}${except(resourceKind)}`}))
      st.principals.forEach((p,i)=> items.push({id:`${st.id}-P${i}`, kind:principalKind, value:p, tip:`${principalKind} ${p}${except(principalKind)}`}))
      st.conditions.forEach((c,i)=> items.push({id:`${st.id}-C${i}`, kind:'Condition', value:`${c.operator} ${c.key}`, subtext:`Values: ${c.values.join(', ')}`, tip:`Values: ${c.values.join(', ')}`}))
      
      for (const it of items) {
        ns.push({ 
          id: it.id, 
          type:'item', 
          data:{ kind:it.kind, value:it.value, tooltip:it.tip, subtext: it.subtext }, 
          position:{x:0,y:0} 
        })
        es.push({ id:`e-${st.id}-${it.id}`, source: st.id, target: it.id })
      }
    })

    const { nodes: laid, edges: laidEdges } = layout(ns, es)
    return { nodes: laid, edges: laidEdges }
  }, [parsed, collapsed])

  const nodeById = useMemo(() => new Map(nodes.map(n => [n.id, n])), [nodes])

  // Refit only when a new policy loads; collapsing a statement keeps the user's pan and zoom.
  const hasGraph = !!parsed
  // Bumped on resize, so a fit that ran before layout is retried.
  const [layoutTick, setLayoutTick] = useState(0)
  useEffect(() => {
    const el = containerRef.current
    if (!el || typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(() => setLayoutTick(t => t + 1))
    ro.observe(el)
    return () => ro.disconnect()
  }, [hasGraph])

  useEffect(() => {
    if (parsed && fittedPolicy.current !== parsed && fitView(nodes)) {
      fittedPolicy.current = parsed
    }
  }, [parsed, nodes, fitView, layoutTick])

  // Scroll pans; Ctrl/Cmd + scroll or a pinch zooms. A native listener, because React's
  // passive onWheel can't stop the browser from zooming the page.
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      if (e.ctrlKey || e.metaKey) {
        const delta = e.deltaY > 0 ? 0.9 : 1.1
        setZoom(prev => Math.max(0.1, Math.min(4, prev * delta)))
        return
      }
      setPan(prev => ({ x: prev.x - e.deltaX, y: prev.y - e.deltaY }))
    }
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => el.removeEventListener('wheel', onWheel)
  }, [hasGraph])

  const handleMouseDown = (e: React.MouseEvent) => {
    setIsDragging(true)
    dragged.current = false
    downPos.current = { x: e.clientX, y: e.clientY }
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y })
  }

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isDragging) {
      if (Math.hypot(e.clientX - downPos.current.x, e.clientY - downPos.current.y) > DRAG_THRESHOLD) {
        dragged.current = true
      }
      setPan({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y
      })
    }
  }

  const handleMouseUp = () => {
    setIsDragging(false)
  }

  const handleNodeClick = (node: Node) => {
    if (dragged.current) return
    if (node.type === 'statement') {
      onToggleStatement(node.id)
    }
  }

  const createCurvedPath = (sourcePos: {x: number, y: number}, targetPos: {x: number, y: number}) => {
    const sourceX = sourcePos.x + NODE_WIDTH
    const sourceY = sourcePos.y + NODE_HEIGHT/2
    
    const targetX = targetPos.x
    const targetY = targetPos.y + NODE_HEIGHT/2
    
    const dx = targetX - sourceX
    const controlX1 = sourceX + dx * 0.5
    const controlX2 = targetX - dx * 0.5
    
    return `M ${sourceX} ${sourceY} C ${controlX1} ${sourceY}, ${controlX2} ${targetY}, ${targetX} ${targetY}`
  }

  const getConnectionPoints = () => {
    const points: Array<{x: number, y: number, type: 'source' | 'target'}> = []
    
    edges.forEach(edge => {
      const sourceNode = nodeById.get(edge.source)
      const targetNode = nodeById.get(edge.target)
      
      if (sourceNode && targetNode) {
        points.push({
          x: sourceNode.position.x + NODE_WIDTH,
          y: sourceNode.position.y + NODE_HEIGHT/2,
          type: 'source'
        })
        
        points.push({
          x: targetNode.position.x,
          y: targetNode.position.y + NODE_HEIGHT/2,
          type: 'target'
        })
      }
    })
    
    return points
  }

  if (!parsed) {
    return (
      <div style={{ 
        width: '100%', 
        height: '100%', 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'center',
        background: '#e0f2fe',
        color: '#666',
        fontSize: '16px'
      }}>
        Load a policy to see the visualization
      </div>
    )
  }

  const bounds = graphBounds(nodes)

  return (
    <div
      className="graph-container"
      ref={containerRef}
      style={{
        width: '100%', 
        height: '100%', 
        background: '#e0f2fe',
        border: '2px solid #0284c7',
        borderRadius: '8px',
        overflow: 'hidden',
        position: 'relative'
      }}>
      <svg
        ref={svgRef}
        data-graph-min-x={bounds ? bounds.minX : 0}
        data-graph-min-y={bounds ? bounds.minY : 0}
        data-graph-width={bounds ? bounds.width : 0}
        data-graph-height={bounds ? bounds.height : 0}
        style={{
          width: '100%', 
          height: '100%',
          cursor: isDragging ? 'grabbing' : 'grab'
        }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
          {edges.map(edge => {
            const sourceNode = nodeById.get(edge.source)
            const targetNode = nodeById.get(edge.target)
            if (!sourceNode || !targetNode) return null
            
            return (
              <path
                key={edge.id}
                d={createCurvedPath(sourceNode.position, targetNode.position)}
                fill="none"
                stroke="#0284c7"
                strokeWidth="3"
                style={{ pointerEvents: 'none' }}
              />
            )
          })}
          
          {getConnectionPoints().map((point, index) => (
            <circle
              key={`connection-${index}`}
              cx={point.x}
              cy={point.y}
              r="4"
              fill="#dc2626"
              stroke="#ffffff"
              strokeWidth="1"
              style={{ pointerEvents: 'none' }}
            />
          ))}
          
          {nodes.map(node => {
            const NodeComponent = node.type === 'policy' ? PolicyNode : 
                                 node.type === 'statement' ? StatementNode : ItemNode
            
            return (
              <g key={node.id} transform={`translate(${node.position.x}, ${node.position.y})`}>
                <foreignObject width={NODE_WIDTH} height={NODE_HEIGHT}>
                  <div onClick={() => handleNodeClick(node)}>
                    <NodeComponent data={node.data} />
                  </div>
                </foreignObject>
              </g>
            )
          })}
        </g>
      </svg>
      
      <div data-testid="zoom-controls" style={{
        position: 'absolute',
        left: '10px',
        bottom: '10px',
        display: 'flex',
        flexDirection: 'column',
        gap: '2px'
      }}>
        <button
          aria-label="Zoom in"
          title="Zoom in"
          onClick={() => setZoom(prev => Math.min(4, prev * 1.2))}
          style={{
            width: '32px',
            height: '32px',
            background: '#0f1630',
            border: '1px solid #1c2442',
            color: '#9aa7c3',
            cursor: 'pointer',
            borderRadius: '4px',
            fontSize: '16px'
          }}
        >
          +
        </button>
        <button
          aria-label="Zoom out"
          title="Zoom out"
          onClick={() => setZoom(prev => Math.max(0.1, prev * 0.8))}
          style={{
            width: '32px',
            height: '32px',
            background: '#0f1630',
            border: '1px solid #1c2442',
            color: '#9aa7c3',
            cursor: 'pointer',
            borderRadius: '4px',
            fontSize: '16px'
          }}
        >
          -
        </button>
        <button
          aria-label="Fit to view"
          title="Fit diagram to view"
          onClick={() => fitView(nodes)}
          style={{
            width: '32px',
            height: '32px',
            background: '#0f1630',
            border: '1px solid #1c2442',
            color: '#9aa7c3',
            cursor: 'pointer',
            borderRadius: '4px',
            fontSize: '10px'
          }}
        >
          ⌂
        </button>
      </div>
    </div>
  )
}

const StatementNode = ({ data }: { data: Record<string, unknown> }) => {
  const effect = data.effect as string
  const sid = data.sid as string | undefined
  const color = effect === 'Allow' ? '#29c26b' : '#f76363'
  return (
    <div
      style={{border:'1px solid #1c2442',borderRadius:12,padding:10,background:'#101a3a', boxSizing:'border-box', width:NODE_WIDTH, minHeight:NODE_HEIGHT}}
      title={sid ? `Sid: ${sid}` : undefined}
    >
      <div style={{fontSize:16, color:'#c6d3ff', fontWeight:600, marginBottom:4}}>{data.title as string}</div>
      <div style={{fontSize:13, color:'#9aa7c3'}}>Effect: <b style={{color}}>{effect}</b>{sid ? <span style={{marginLeft:8, opacity:.8}}>• Sid: {sid}</span> : null}</div>
    </div>
  )
}

const ItemNode = ({ data }: { data: Record<string, unknown> }) => {
  const value = data.value
  const primary = ellipsizeMiddle(String(value), 34)
  const secondary = data.subtext as string | undefined
  return (
    <div title={data.tooltip as string | undefined} style={{border:'1px solid #1c2442',borderRadius:12,padding:10,background:'#0c1533', boxSizing:'border-box', width:NODE_WIDTH, minHeight:NODE_HEIGHT, display:'flex', alignItems:'center', gap:10}}>
      {BADGE_KINDS.includes(data.kind as string) && typeof value === 'string' && <ServiceBadge value={value} />}
      <div style={{ overflow:'hidden' }}>
        <div style={{fontSize:13, color:'#9aa7c3', marginBottom:2}}>{data.kind as string}</div>
        <div style={{fontSize:15, color:'#eaeef7', whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis'}}>{primary}</div>
        {secondary && <div style={{fontSize:12, color:'#9aa7c3', marginTop:2, whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis'}}>{ellipsizeMiddle(secondary, 40)}</div>}
      </div>
    </div>
  )
}

const PolicyNode = ({ data }: { data: Record<string, unknown> }) => (
  <div style={{border:'1px solid #1c2442',borderRadius:12,padding:12,background:'#0b1228', boxSizing:'border-box', width:NODE_WIDTH, minHeight:NODE_HEIGHT}}>
    <div style={{fontSize:16, color:'#9cc2ff', fontWeight:600, marginBottom:4}}>{data.label as string}</div>
    <div style={{fontSize:13, color:'#9aa7c3'}}>Version: {(data.version as string | undefined) ?? '—'}</div>
  </div>
)
