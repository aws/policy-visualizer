// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useState } from 'react'
import type { ParsedPolicy } from '../policy/types'
import { buildSummaryRows } from '../policy/optimize'

export default function SummaryTable({ parsed }: { parsed: ParsedPolicy | null }) {
  const [isExpanded, setIsExpanded] = useState(false)
  
  if (!parsed) return null
  
  const { rows, total } = buildSummaryRows(parsed)
  
  return (
    <div style={{ background: '#1a202c', borderRadius: '8px', overflow: 'hidden' }}>
      <div 
        style={{ 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center',
          background: '#2d3748', 
          padding: '12px 16px',
          cursor: 'pointer',
          borderBottom: isExpanded ? '1px solid #4a5568' : 'none'
        }}
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <h3 style={{ margin: '0', color: '#fff', fontSize: '16px' }}>Policy summary</h3>
        <span style={{ color: '#9aa7c3', fontSize: '18px', transform: isExpanded ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s' }}>
          ▼
        </span>
      </div>

      {isExpanded && (
        <div style={{ padding: '16px' }}>
          <div style={{ maxHeight: '400px', overflowY: 'auto', background: '#2d3748', borderRadius: '6px' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
              <thead>
                <tr style={{ background: '#4a5568' }}>
                  <th style={{ padding: '8px', textAlign: 'left', color: '#fff', borderBottom: '1px solid #718096' }}>Stmt</th>
                  <th style={{ padding: '8px', textAlign: 'left', color: '#fff', borderBottom: '1px solid #718096' }}>Effect</th>
                  <th style={{ padding: '8px', textAlign: 'left', color: '#fff', borderBottom: '1px solid #718096' }}>Action</th>
                  <th style={{ padding: '8px', textAlign: 'left', color: '#fff', borderBottom: '1px solid #718096' }}>Resource</th>
                  <th style={{ padding: '8px', textAlign: 'left', color: '#fff', borderBottom: '1px solid #718096' }}>Conditions</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r,i)=>(
                  <tr key={i} style={{ borderBottom: '1px solid #4a5568' }}>
                    <td style={{ padding: '8px', color: '#e2e8f0' }}>{r.stmt}</td>
                    <td style={{ padding: '8px', color: r.effect==='Allow' ? '#29c26b' : '#f76363' }}>{r.effect}</td>
                    <td style={{ padding: '8px', color: '#e2e8f0', fontSize: '12px', wordBreak: 'break-all' }}>{r.action}</td>
                    <td style={{ padding: '8px', color: '#e2e8f0', fontSize: '12px', wordBreak: 'break-all' }}>{r.resource}</td>
                    <td style={{ padding: '8px', color: '#ffb86b', fontSize: '12px' }}>{r.condition}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {total > rows.length && (
            <p style={{ fontSize: '12px', color: '#ffb86b', margin: '8px 0 0 0' }}>
              Showing the first {rows.length.toLocaleString('en-US')} of {total.toLocaleString('en-US')} rows.
            </p>
          )}
        </div>
      )}
    </div>
  )
}
