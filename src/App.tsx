// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useMemo, useState } from 'react'
import PolicyUploader from './components/PolicyUploader'
import Graph from './components/Graph'
import SummaryTable from './components/SummaryTable'
import PolicyAnalysis from './components/PolicyAnalysis'
import type { ParsedPolicy } from './policy/types'
import { exportElementAsPNG, exportElementAsPDF } from './utils/export'
import { Redactor, redactPolicy } from './policy/redact'

export default function App() {
  const [parsed, setParsed] = useState<ParsedPolicy|null>(null)
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({})
  const [exportError, setExportError] = useState<string | null>(null)
  const [redact, setRedact] = useState(false)

  // Display uses the redacted copy; analysis and the Optimize download use the real policy.
  const redaction = useMemo(() => {
    if (!parsed || !redact) return null
    const redactor = new Redactor()
    return { policy: redactPolicy(parsed, redactor), redactor }
  }, [parsed, redact])
  const shown = redaction?.policy ?? parsed

  function toggle(stmtId: string) {
    setCollapsed(prev => ({ ...prev, [stmtId]: !prev[stmtId] }))
  }

  const stmtControls = useMemo(()=>{
    if (!shown) return null
    return (
      <div className="panel">
        <h3>Statements</h3>
        <div style={{ display:'flex', gap:8, marginBottom:8 }}>
          <button className="btn secondary" onClick={()=>setCollapsed(Object.fromEntries(shown.statements.map(s => [s.id, true])))}>Collapse all</button>
          <button className="btn secondary" onClick={()=>setCollapsed(Object.fromEntries(shown.statements.map(s => [s.id, false])))}>Expand all</button>
        </div>
        {shown.statements.map((s, idx) => (
          <div key={s.id} style={{display:'flex', justifyContent:'space-between', alignItems:'center', padding:'6px 0', borderBottom:'1px solid #1c2442'}}>
            <div>
              <div style={{fontSize:13, color:'#c6d3ff'}}>Statement {idx+1} {s.sid ? `(${s.sid})` : ''} {collapsed[s.id] ? ' (collapsed)' : ''}</div>
              <div style={{fontSize:13, color:'#9aa7c3'}}>
                Effect: <b style={{color: s.effect==='Allow' ? '#29c26b' : '#f76363'}}>{s.effect}</b> · Actions: <b>{s.actions.length}</b> · Resources: <b>{s.resources.length}</b> · Conditions: <b>{s.conditions.length}</b>
              </div>
            </div>
            <button className="btn secondary" onClick={()=>toggle(s.id)}>{collapsed[s.id] ? 'Expand' : 'Collapse'}</button>
          </div>
        ))}
      </div>
    )
  }, [shown, collapsed])

  async function runExport(kind: 'PNG' | 'PDF') {
    const el = document.querySelector('.graph-container') as HTMLElement | null
    if (!el) return
    setExportError(null)
    try {
      await (kind === 'PNG' ? exportElementAsPNG(el) : exportElementAsPDF(el))
    } catch (e: unknown) {
      console.error(`Export ${kind} failed:`, e)
      setExportError(`Export ${kind} failed${e instanceof Error && e.message ? `: ${e.message}` : '.'}`)
    }
  }

  return (
    <div className="app">
      <div className="sidebar">
        <PolicyUploader onParsed={(p)=>{ setParsed(p); setCollapsed({}) }} redacted={redact} />
        {stmtControls}
        <PolicyAnalysis parsed={parsed} displayParsed={redaction?.policy} redactor={redaction?.redactor} />
        <SummaryTable parsed={shown} />
        <div className="foot">Click a <b>Statement</b> node to toggle collapse. Drag or scroll the diagram to pan; Ctrl/Cmd + scroll or pinch to zoom.</div>
      </div>
      <div className="main">
        <div className="toolbar">
          <h1>Policy Visualizer for AWS</h1>
          {exportError && <span role="alert" style={{ color: '#f76363', fontSize: 13 }}>{exportError}</span>}
          <label title="Replace account IDs, resource names, Sids, and condition values with placeholders everywhere on the page, in PNG/PDF exports, and in copied findings. Hides the pasted policy text." style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, color: '#c6d3ff', cursor: 'pointer' }}>
            <input type="checkbox" checked={redact} onChange={e => setRedact(e.target.checked)} />
            Redact names and IDs
          </label>
          <button className="btn secondary" onClick={() => runExport('PNG')} disabled={!parsed}>Export PNG</button>
          <button className="btn secondary" onClick={() => runExport('PDF')} disabled={!parsed}>Export PDF</button>
        </div>
        <div className="rf-wrapper">
          <Graph parsed={shown} collapsed={collapsed} onToggleStatement={(id)=>toggle(id)} />
        </div>
      </div>
    </div>
  )
}
