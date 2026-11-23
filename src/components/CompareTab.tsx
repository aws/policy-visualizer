// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useMemo, useState } from 'react'
import type { ParsedPolicy } from '../policy/types'
import { loadPolicyText } from '../policy/input'
import { describeParseError } from '../policy/parse'
import { analyzePolicy, type AnalyzeOptions, type Finding } from '../policy/findings'
import { diffPolicies, hasChanges, type ElementDiff } from '../policy/diff'
import { redactPolicy, type Redactor } from '../policy/redact'

const box = { background: '#2d3748', borderRadius: '6px', padding: '10px', marginBottom: '8px' }

function DiffRows({ title, diff, tx }: { title: string; diff: ElementDiff; tx: (t: string) => string }) {
  if (!diff.added.length && !diff.removed.length) return null
  return (
    <div style={box}>
      <div style={{ fontSize: '13px', color: '#fff', marginBottom: '4px' }}>{title}</div>
      <ul style={{ listStyle: 'none', margin: 0, padding: 0, fontSize: '12px', overflowWrap: 'anywhere' }}>
        {diff.added.map(v => <li key={`+${v}`} style={{ color: '#29c26b' }}>+ {tx(v)}</li>)}
        {diff.removed.map(v => <li key={`-${v}`} style={{ color: '#f76363' }}>- {tx(v)}</li>)}
      </ul>
    </div>
  )
}

const findingText = (f: Finding) =>
  `${f.statement ? `Statement ${f.statement}: ` : ''}${f.severity.toUpperCase()}: ${f.title}. ${f.detail}`

export default function CompareTab({ after, options, redactor }: { after: ParsedPolicy; options: AnalyzeOptions; redactor?: Redactor | null }) {
  const [text, setText] = useState('')
  const [before, setBefore] = useState<ParsedPolicy | null>(null)
  const [error, setError] = useState<string | null>(null)

  const diff = useMemo(() => before
    ? diffPolicies(before, after, analyzePolicy(before, options), analyzePolicy(after, options))
    : null, [before, after, options])

  // Register the earlier version's values too, so both versions share placeholders.
  const tx = useMemo(() => {
    if (!redactor) return (t: string) => t
    if (before) redactPolicy(before, redactor)
    return (t: string) => redactor.text(t)
  }, [redactor, before])

  function compare() {
    try {
      setBefore(loadPolicyText(text))
      setError(null)
    } catch (e: unknown) {
      setBefore(null)
      setError(describeParseError(e))
    }
  }

  return (
    <>
      <h3 style={{ margin: '0 0 8px 0', color: '#fff', fontSize: '16px' }}>Compare with a previous version</h3>
      <p style={{ fontSize: '12px', color: '#9aa7c3', margin: '0 0 8px 0' }}>
        Paste the earlier version. The loaded policy is treated as the new version.
      </p>
      {redactor
        ? <div style={{ fontSize: '12px', color: '#9aa7c3', border: '1px dashed #4a5568', borderRadius: '6px', padding: '10px', marginBottom: '4px' }}>Policy text is hidden while redaction is on.</div>
        : <textarea aria-label="Previous policy version" value={text} onChange={e => setText(e.target.value)} style={{ minHeight: '100px' }} />}
      <button className="btn" onClick={compare} disabled={!text.trim()} style={{ margin: '6px 0 10px 0' }}>Show changes</button>
      {error && <div style={{ color: '#f76363', fontSize: '13px', marginBottom: '8px' }}>{error}</div>}
      {diff && !hasChanges(diff) && <div style={{ fontSize: '13px', color: '#9aa7c3' }}>No differences.</div>}
      {diff && hasChanges(diff) && (
        <div data-testid="policy-diff">
          {(diff.statementCount.before !== diff.statementCount.after || diff.version.before !== diff.version.after) && (
            <div style={{ ...box, fontSize: '12px', color: '#e2e8f0' }}>
              {diff.statementCount.before !== diff.statementCount.after && <div>Statements: {diff.statementCount.before} to {diff.statementCount.after}</div>}
              {diff.version.before !== diff.version.after && <div>Version: {diff.version.before ?? 'none'} to {diff.version.after ?? 'none'}</div>}
            </div>
          )}
          <DiffRows title="Statements" diff={diff.statements} tx={tx} />
          <DiffRows title="Allowed actions" diff={diff.allowActions} tx={tx} />
          <DiffRows title="Allowed resources" diff={diff.allowResources} tx={tx} />
          <DiffRows title="Denied actions" diff={diff.denyActions} tx={tx} />
          <DiffRows title="Denied resources" diff={diff.denyResources} tx={tx} />
          <DiffRows title="Principals" diff={diff.principals} tx={tx} />
          <DiffRows title="Conditions" diff={diff.conditions} tx={tx} />
          <DiffRows title="Sids" diff={diff.sids} tx={tx} />
          <DiffRows title="Findings" tx={tx} diff={{
            added: diff.newFindings.map(findingText),
            removed: diff.resolvedFindings.map(findingText),
          }} />
        </div>
      )}
      <p style={{ fontSize: '12px', color: '#9aa7c3', margin: '8px 0 0 0' }}>
        This compares the policy text statement by statement and element by element. It does not evaluate effective permissions.
      </p>
    </>
  )
}
