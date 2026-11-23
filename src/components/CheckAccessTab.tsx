// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useState } from 'react'
import type { ParsedPolicy } from '../policy/types'
import { evaluateAccess, type AccessResult, type Decision } from '../policy/evaluate'
import { isGuardrail, type PolicyType } from '../policy/policyType'

const DECISION_COLOR: Record<Decision, string> = {
  'explicit-deny': '#f76363',
  'implicit-deny': '#f76363',
  allowed: '#29c26b',
  conditional: '#ffb86b',
  'depends-on-principal': '#ffb86b',
  'depends-on-resource': '#ffb86b',
}

const input = { display: 'block', width: '100%', boxSizing: 'border-box' as const, marginTop: '4px', padding: '5px 6px', background: '#0a1430', color: '#eaeef7', border: '1px solid #4a5568', borderRadius: '4px', fontSize: '13px' }
const labelStyle = { display: 'block', fontSize: '12px', color: '#9aa7c3', marginBottom: '8px' }

// Typed fields are masked while redacting, since their text is not redacted.
// autoComplete "new-password" stops browsers filling a saved password into a masked field.
export default function CheckAccessTab({ parsed, policyType, tx = t => t, redacted = false }: { parsed: ParsedPolicy; policyType: PolicyType; tx?: (t: string) => string; redacted?: boolean }) {
  const [action, setAction] = useState('')
  const [resource, setResource] = useState('')
  const [principal, setPrincipal] = useState('')
  const [result, setResult] = useState<AccessResult | null>(null)
  const hasPrincipals = parsed.statements.some(s => s.raw.Principal !== undefined || s.raw.NotPrincipal !== undefined)

  function check() {
    setResult(evaluateAccess(parsed, {
      action: action.trim(),
      resource: resource.trim() || undefined,
      principal: principal.trim() || undefined,
    }))
  }

  return (
    <>
      <h3 style={{ margin: '0 0 8px 0', color: '#fff', fontSize: '16px' }}>Does this policy allow it?</h3>
      <div role="note" style={{ border: '1px solid #ffb86b', background: '#3a2f1f', color: '#ffd9a8', borderRadius: '6px', padding: '8px 10px', fontSize: '12px', marginBottom: '12px' }}>
        <strong>This policy only.</strong> Conditions are listed, not evaluated. Other policies that apply to a real
        request (identity, resource-based, SCPs, RCPs, permissions boundaries, session policies) are not considered.
        Use the IAM policy simulator for a full answer.
      </div>
      <label style={labelStyle}>Action
        <input style={input} value={action} onChange={e => setAction(e.target.value)} placeholder="service:Action, e.g. s3:GetObject" />
      </label>
      <label style={labelStyle}>Resource ARN (optional)
        <input style={input} type={redacted ? 'password' : 'text'} autoComplete={redacted ? 'new-password' : 'off'} value={resource} onChange={e => setResource(e.target.value)} placeholder="arn:aws:s3:::bucket-name/key" />
      </label>
      {hasPrincipals && (
        <label style={labelStyle}>Caller principal (optional)
          <input style={input} type={redacted ? 'password' : 'text'} autoComplete={redacted ? 'new-password' : 'off'} value={principal} onChange={e => setPrincipal(e.target.value)} placeholder="Role ARN, account ID, or service principal" />
        </label>
      )}
      <button className="btn" onClick={check} disabled={!/^[^:\s]+:[^:\s]+$/.test(action.trim()) && action.trim() !== '*'}>Check</button>

      {result && (
        <div data-testid="access-result" data-decision={result.decision} style={{ marginTop: '12px' }}>
          <div style={{ fontSize: '14px', fontWeight: 600, color: DECISION_COLOR[result.decision], marginBottom: '6px' }}>
            {tx(result.summary)}
          </div>
          {isGuardrail(policyType) && (result.decision === 'allowed' || result.decision === 'conditional') && (
            <div style={{ fontSize: '12px', color: '#9aa7c3', marginBottom: '6px' }}>
              This policy type only sets a maximum. The request also needs an identity or resource-based policy that grants it.
            </div>
          )}
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {result.matches.filter(m => m.match !== 'no').map(m => (
              <li key={m.statement} style={{ background: '#2d3748', borderRadius: '4px', padding: '6px 8px', marginBottom: '4px', fontSize: '12px', color: '#e2e8f0' }}>
                <b style={{ color: m.effect === 'Allow' ? '#29c26b' : '#f76363' }}>{m.effect}</b> Statement {m.statement}{m.sid ? ` (${tx(m.sid)})` : ''}
                {m.match === 'unknown' ? ' may match' : ' matches'}
                {m.notes.map((n, i) => <div key={i} style={{ color: '#9aa7c3' }}>{tx(n)}</div>)}
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  )
}
