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

// Item kinds whose values are actions or ARNs, and so carry a service badge.
const BADGE_KINDS = ['Action', 'NotAction', 'Resource', 'NotResource']

const NODE_WIDTH = 340
const NODE_HEIGHT = 80
const FIT_MARGIN = 24
// Fit-to-view never shrinks below this, so text stays readable. Graphs too
// tall to fit at this zoom are fitted to the width and shown from the top;
// scroll or drag to see the rest.
const MIN_FIT_ZOOM = 0.75
// Zoom controls sit in the bottom-left corner. Fitting keeps the diagram to
// the right of them: 10px inset + 32px buttons + 10px clearance.
const CONTROLS_GUTTER = 52
// Mouse movement, in pixels, beyond which a press counts as a pan.
const DRAG_THRESHOLD = 3

// Bounding box of all laid-out nodes in graph coordinates.
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

// Center-symmetric layout algorithm with intelligent spacing
function layout(nodes: Node[], edges: Edge[]) {
  const levels: { [key: number]: Node[] } = {}
  const nodeMap: { [key: string]: Node } = {}
  
  nodes.forEach(node => {
    nodeMap[node.id] = node
    const level = node.type === 'policy' ? 0 : node.type === 'statement' ? 1 : 2
    if (!levels[level]) levels[level] = []
    levels[level].push(node)
  })

  // Position nodes by level with intelligent spacing
  Object.keys(levels).forEach(levelKey => {
    const level = parseInt(levelKey)
    const levelNodes = levels[level]
    
    let spacing: number
    
    if (level === 1) { // Statement level - consider child nodes
      const statementNodes = levelNodes
      const childNodes = levels[2] || []
      
      // Calculate average children per statement
      const avgChildrenPerStatement = childNodes.length / Math.max(statementNodes.length, 1)
      
      // Adjust spacing based on both statement count and child density
      if (statementNodes.length <= 2) {
        // For 1-2 statements, increase spacing more if they have many children
        if (avgChildrenPerStatement > 6) {
          spacing = NODE_HEIGHT + 180 // Extra space for statements with many children
        } else if (avgChildrenPerStatement > 3) {
          spacing = NODE_HEIGHT + 150 // More space for moderate children
        } else {
          spacing = NODE_HEIGHT + 120 // Standard extra space for few statements
        }
      } else if (statementNodes.length <= 4) {
        // For 3-4 statements, moderate spacing adjustment
        if (avgChildrenPerStatement > 4) {
          spacing = NODE_HEIGHT + 100
        } else {
          spacing = NODE_HEIGHT + 80
        }
      } else if (statementNodes.length <= 6) {
        // For 5-6 statements, less spacing adjustment
        spacing = NODE_HEIGHT + 60
      } else {
        // For many statements, compact spacing
        spacing = NODE_HEIGHT + 40
      }
    } else {
      // For other levels (policy and items), use simpler spacing
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
    
    // Calculate total height needed for this level
    const totalHeight = (levelNodes.length - 1) * spacing
    const startY = 300 - totalHeight / 2 // Center around y=300

    levelNodes.forEach((node, index) => {
      node.position = {
        x: level * (NODE_WIDTH + 120) + 100, // Horizontal spacing
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
  // Where the mouse went down, and whether it has since moved far enough to
  // count as a drag. A drag that ends on a statement node must not toggle it.
  const downPos = useRef({ x: 0, y: 0 })
  const dragged = useRef(false)
  const svgRef = useRef<SVGSVGElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const fittedPolicy = useRef<ParsedPolicy | null>(null)

  // Scale and center the view so the whole graph is visible in the container.
  // Returns false when the container has no size yet, so the caller can
  // retry once it is laid out.
  const fitView = useCallback((ns: Node[]): boolean => {
    const el = containerRef.current
    const bounds = graphBounds(ns)
    if (!el || !bounds) return false
    const cw = el.clientWidth
    const ch = el.clientHeight
    if (!cw || !ch) return false
    // Usable width runs from the controls gutter to the right margin.
    const usableW = cw - CONTROLS_GUTTER - FIT_MARGIN
    const fitWidth = usableW / bounds.width
    const fitHeight = (ch - 2 * FIT_MARGIN) / bounds.height
    // Center horizontally within the usable width, never left of the gutter.
    const panX = (z: number) =>
      CONTROLS_GUTTER + Math.max(0, (usableW - bounds.width * z) / 2) - bounds.minX * z
    const scale = Math.min(fitWidth, fitHeight, 1)
    if (scale >= MIN_FIT_ZOOM) {
      setZoom(scale)
      setPan({ x: panX(scale), y: (ch - bounds.height * scale) / 2 - bounds.minY * scale })
      return true
    }
    // Too big to fit readably: fit the width (within the floor) and start at the top.
    const z = Math.max(MIN_FIT_ZOOM, Math.min(fitWidth, 1))
    setZoom(z)
    setPan({ x: panX(z), y: FIT_MARGIN - bounds.minY * z })
    return true
  }, [])

  // Nodes and edges are derived from props during render, so the diagram
  // never shows a previous policy for a frame (for example, real values for
  // one render after redaction is switched on).
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
      // NotAction/NotResource/NotPrincipal mean "everything except these", so
      // label them distinctly rather than as plain Action/Resource/Principal.
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

  // Edges look nodes up by id on every render; a Map keeps that linear.
  const nodeById = useMemo(() => new Map(nodes.map(n => [n.id, n])), [nodes])

  // Fit the view when a new policy is loaded. Collapsing or expanding a
  // statement keeps the user's pan and zoom; the home button refits.
  // The container only exists while a policy is shown.
  const hasGraph = !!parsed
  // Bumped when the container is resized, so a fit that ran before layout
  // (container size 0) is retried.
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

  // Scroll pans; Ctrl/Cmd + scroll, or a trackpad pinch (reported with
  // ctrlKey), zooms. React's onWheel is passive and can't stop the browser
  // from also zooming the whole page, so this is a native listener.
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

  // Handle mouse events for pan and zoom
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

  // Create curved path between specific connection points
  const createCurvedPath = (sourcePos: {x: number, y: number}, targetPos: {x: number, y: number}) => {
    // Source connection point (right side of source node)
    const sourceX = sourcePos.x + NODE_WIDTH
    const sourceY = sourcePos.y + NODE_HEIGHT/2
    
    // Target connection point (left side of target node)
    const targetX = targetPos.x
    const targetY = targetPos.y + NODE_HEIGHT/2
    
    // Create smooth curve
    const dx = targetX - sourceX
    const controlX1 = sourceX + dx * 0.5
    const controlX2 = targetX - dx * 0.5
    
    return `M ${sourceX} ${sourceY} C ${controlX1} ${sourceY}, ${controlX2} ${targetY}, ${targetX} ${targetY}`
  }

  // Get connection points for nodes
  const getConnectionPoints = () => {
    const points: Array<{x: number, y: number, type: 'source' | 'target'}> = []
    
    edges.forEach(edge => {
      const sourceNode = nodeById.get(edge.source)
      const targetNode = nodeById.get(edge.target)
      
      if (sourceNode && targetNode) {
        // Source connection point (right side)
        points.push({
          x: sourceNode.position.x + NODE_WIDTH,
          y: sourceNode.position.y + NODE_HEIGHT/2,
          type: 'source'
        })
        
        // Target connection point (left side)
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
          {/* Render edges */}
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
          
          {/* Render connection points */}
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
          
          {/* Render nodes */}
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
      
      {/* Zoom controls */}
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
      style={{border:'1px solid #1c2442',borderRadius:12,padding:10,background:'#101a3a', width:NODE_WIDTH-20, minHeight:NODE_HEIGHT-20}}
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
    <div title={data.tooltip as string | undefined} style={{border:'1px solid #1c2442',borderRadius:12,padding:10,background:'#0c1533', width:NODE_WIDTH-20, minHeight:NODE_HEIGHT-20, display:'flex', alignItems:'center', gap:10}}>
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
  <div style={{border:'1px solid #1c2442',borderRadius:12,padding:12,background:'#0b1228', width:NODE_WIDTH-20, minHeight:NODE_HEIGHT-20}}>
    <div style={{fontSize:16, color:'#9cc2ff', fontWeight:600, marginBottom:4}}>{data.label as string}</div>
    <div style={{fontSize:13, color:'#9aa7c3'}}>Version: {(data.version as string | undefined) ?? '—'}</div>
  </div>
)
