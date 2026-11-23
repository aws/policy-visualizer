// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useState, type ReactNode } from 'react'
import type { ParsedPolicy, ParsedStatement } from '../policy/types'
import { buildOptimizedPolicy, buildPermissionRows, permissionRowCount, versionWarning, type PermissionRow, type PermissionStatus } from '../policy/optimize'
import { analyzePolicy, describeSubject, type Finding, type Severity } from '../policy/findings'
import { detectPolicyType, guardrailNotice, isGuardrail, POLICY_TYPES, sizeLimit, type PolicyType } from '../policy/policyType'
import { findingsMarkdown } from '../policy/markdown'
import type { Redactor } from '../policy/redact'
import CompareTab from './CompareTab'
import CheckAccessTab from './CheckAccessTab'
import { download } from '../utils/export'

type Tab = 'overview' | 'readable' | 'optimize' | 'compare' | 'check'
const TABS: { id: Tab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'readable', label: 'Human Readable' },
  { id: 'optimize', label: 'Optimize' },
  { id: 'compare', label: 'Compare' },
  { id: 'check', label: 'Check access' },
]

function hasWildcard(list: string[]) { return list.some(v => v === '*' || v.includes('*')) }

const SEVERITY_STYLE: Record<Severity, { label: string; color: string }> = {
  high: { label: 'High', color: '#f76363' },
  medium: { label: 'Medium', color: '#ffb86b' },
  low: { label: 'Low', color: '#9aa7c3' },
  info: { label: 'Info', color: '#5bb8ff' },
}

function FindingsList({ findings, tx }: { findings: Finding[]; tx: (t: string) => string }) {
  if (!findings.length) {
    return <div style={{ fontSize: '13px', color: '#29c26b' }}>No issues found by the offline checks.</div>
  }
  return (
    <ul data-testid="findings" style={{ listStyle: 'none', padding: 0, margin: 0 }}>
      {findings.map((f, i) => {
        const { label, color } = SEVERITY_STYLE[f.severity]
        return (
          <li key={i} data-severity={f.severity} style={{ borderLeft: `3px solid ${color}`, background: '#2d3748', padding: '8px 10px', borderRadius: '4px', marginBottom: '6px' }}>
            <div style={{ fontSize: '13px', color: '#fff' }}>
              <span style={{ color, fontWeight: 700, fontSize: '11px', textTransform: 'uppercase', marginRight: '6px' }}>{label}</span>
              {tx(f.title)}
              {f.statement ? <span style={{ color: '#9aa7c3' }}> · Statement {f.statement}{f.sid ? ` (${tx(f.sid)})` : ''}</span> : null}
            </div>
            <div style={{ fontSize: '12px', color: '#e2e8f0', marginTop: '2px' }}>{tx(f.detail)}</div>
          </li>
        )
      })}
    </ul>
  )
}

const serviceIcons: Record<string, string> = {
  's3': '🪣', 'ec2': '🖥️', 'lambda': 'λ', 'iam': '👤', 'rds': '🗄️', 'cloudformation': '📚',
  'sns': '📢', 'sqs': '📬', 'dynamodb': '⚡', 'cloudwatch': '📊', 'kms': '🔐', 'sts': '🎫'
}

function getServiceIcon(action: string): string {
  const service = action.split(':')[0]?.toLowerCase()
  return serviceIcons[service] || '⚙️'
}

// Policy values render as React text nodes, never HTML, so a pasted policy can't inject markup.
function ActionDescription({ action }: { action: string }) {
  const parts = action.split(':')
  if (parts.length !== 2) return <>{action}</>
  const [service, op] = parts
  let operation: ReactNode
  if (op === '*') {
    operation = <strong>perform any action</strong>
  } else if (op.endsWith('*')) {
    operation = <>perform <strong>any action</strong> starting with {op.slice(0, -1)}</>
  } else {
    operation = <>perform {op.replace(/([A-Z])/g, ' $1').toLowerCase()}</>
  }
  return <>{getServiceIcon(action)} {operation} in {service}</>
}

function TranslatedStatement({ statement }: { statement: ParsedStatement }) {
  const allow = statement.effect === 'Allow'
  const effectText = statement.notAction
    ? (allow ? 'is allowed to perform every action except' : 'is denied from performing every action except')
    : (allow ? 'is allowed to' : 'is denied from')
  const effect = <strong style={{ color: allow ? '#29c26b' : '#f76363' }}>{effectText}</strong>

  const resourceDescriptions = statement.resources.length
    ? statement.resources.join(', ')
    : 'any resource'
  const resourceLabel = statement.notResource ? 'on every resource except' : 'on resources'

  const conditionDescriptions = statement.conditions.length
    ? statement.conditions.map(c => `${c.operator} ${c.key}: ${c.values.join(', ')}`).join('; ')
    : 'No conditions'

  return (
    <>
      {describeSubject(statement)} {effect}:<br />
      <ul style={{ margin: '5px 0', paddingLeft: '20px' }}>
        {statement.actions.map((action, i) => (
          <li key={i}>
            {statement.notAction ? <>{getServiceIcon(action)} {action}</> : <ActionDescription action={action} />}
          </li>
        ))}
      </ul>
      {resourceLabel}: <code style={{ background: '#1c2442', padding: '2px 4px', borderRadius: '3px' }}>{resourceDescriptions}</code><br />
      <strong>Conditions:</strong> {conditionDescriptions}
    </>
  )
}

// Analysis runs on the real policy; displayParsed and redactor are for what is shown.
export default function PolicyAnalysis({ parsed, displayParsed, redactor }: {
  parsed: ParsedPolicy | null
  displayParsed?: ParsedPolicy | null
  redactor?: Redactor | null
}) {
  const tx = useMemo(() => (redactor ? (t: string) => redactor.text(t) : (t: string) => t), [redactor])
  const [activeTab, setActiveTab] = useState<Tab>('overview')
  const [permissions, setPermissions] = useState<PermissionRow[]>([])
  const [isExpanded, setIsExpanded] = useState(false)
  const [accountId, setAccountId] = useState('')
  const accountValid = /^\d{12}$/.test(accountId)
  // 'auto' follows detectPolicyType; a picked type holds until the next policy loads.
  const [typeChoice, setTypeChoice] = useState<PolicyType | 'auto'>('auto')
  const [copyStatus, setCopyStatus] = useState<string | null>(null)
  const [copyFallback, setCopyFallback] = useState<string | null>(null)
  const detectedType = useMemo(() => (parsed ? detectPolicyType(parsed) : 'identity'), [parsed])
  const policyType = typeChoice === 'auto' ? detectedType : typeChoice
  const options = useMemo(() => ({ accountId: accountValid ? accountId : undefined, policyType }), [accountId, accountValid, policyType])

  useEffect(() => {
    setTypeChoice('auto')
    setCopyStatus(null)
    setCopyFallback(null)
  }, [parsed])

  const analysis = useMemo(() => {
    if (!parsed) return null
    const total = parsed.statements.length
    const allow = parsed.statements.filter(s => s.effect === 'Allow').length
    const deny = total - allow
    let wildActions = 0, wildResources = 0, noConditions = 0
    for (const s of parsed.statements) {
      // A wildcard in NotAction/NotResource narrows the exception, so it is not a wildcard grant.
      if (!s.notAction && hasWildcard(s.actions)) wildActions++
      if (!s.notResource && hasWildcard(s.resources)) wildResources++
      if (!s.conditions.length) noConditions++
    }
    const findings = analyzePolicy(parsed, options)
    return { total, allow, deny, wildActions, wildResources, noConditions, findings }
  }, [parsed, options])

  async function copyMarkdown() {
    if (!parsed || !analysis) return
    const size = sizeLimit(policyType)
    const md = findingsMarkdown(analysis.findings, {
      policyType,
      typeDetected: typeChoice === 'auto',
      statements: parsed.statements.length,
      charCount: parsed.charCount,
      sizeLimit: size?.limit,
      transform: redactor ? t => redactor.text(t) : undefined,
    })
    try {
      await navigator.clipboard.writeText(md)
      setCopyFallback(null)
      setCopyStatus(redactor ? 'Copied (redacted).' : 'Copied.')
    } catch {
      // Clipboard access can be blocked; show the text to copy by hand.
      setCopyFallback(md)
      setCopyStatus('Copy the Markdown below.')
    }
  }

  // Only the rows the table shows are built; the total is counted separately.
  useEffect(() => {
    setPermissions(parsed ? buildPermissionRows(parsed) : [])
  }, [parsed])
  const permissionTotal = useMemo(() => (parsed ? permissionRowCount(parsed) : 0), [parsed])
  const oldVersion = useMemo(() => (parsed ? versionWarning(parsed) : undefined), [parsed])

  const updatePermissionStatus = (index: number, status: PermissionStatus) => {
    setPermissions(prev => prev.map((p, i) => i === index ? { ...p, status } : p))
  }

  const downloadOptimizedPolicy = () => {
    if (!parsed) return
    const optimizedPolicy = buildOptimizedPolicy(parsed, permissions)

    const blob = new Blob([JSON.stringify(optimizedPolicy, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    download(url, 'optimized-policy.json')
    URL.revokeObjectURL(url)
  }

  if (!parsed || !analysis) return null

  const tabStyle = (tab: string) => ({
    padding: '8px 12px',
    background: activeTab === tab ? '#2d3748' : 'transparent',
    border: 'none',
    color: activeTab === tab ? '#fff' : '#9aa7c3',
    cursor: 'pointer',
    borderRadius: '4px 4px 0 0',
    fontSize: '13px'
  })

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
        <h3 style={{ margin: '0', color: '#fff', fontSize: '16px' }}>Policy Analysis</h3>
        <span style={{ color: '#9aa7c3', fontSize: '18px', transform: isExpanded ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s' }}>
          ▼
        </span>
      </div>

      {isExpanded && (
        <>
          <div style={{ display: 'flex', flexWrap: 'wrap', background: '#2d3748', borderBottom: '1px solid #4a5568' }}>
            {TABS.map(t => (
              <button key={t.id} style={tabStyle(t.id)} onClick={() => setActiveTab(t.id)}>{t.label}</button>
            ))}
          </div>

          <div style={{ padding: '16px' }}>
            {activeTab === 'overview' && (
              <>
                <h3 style={{ margin: '0 0 16px 0', color: '#fff', fontSize: '16px' }}>Policy Analysis</h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', marginBottom: '16px' }}>
                  <div style={{ background: '#2d3748', padding: '12px', borderRadius: '6px', textAlign: 'center' }}>
                    <div style={{ fontSize: '12px', color: '#9aa7c3', marginBottom: '4px' }}>Statements</div>
                    <div style={{ fontSize: '18px', color: '#fff', fontWeight: 'bold' }}>{analysis.total}</div>
                  </div>
                  <div style={{ background: '#2d3748', padding: '12px', borderRadius: '6px', textAlign: 'center' }}>
                    <div style={{ fontSize: '12px', color: '#9aa7c3', marginBottom: '4px' }}>Allow</div>
                    <div style={{ fontSize: '18px', color: '#29c26b', fontWeight: 'bold' }}>{analysis.allow}</div>
                  </div>
                  <div style={{ background: '#2d3748', padding: '12px', borderRadius: '6px', textAlign: 'center' }}>
                    <div style={{ fontSize: '12px', color: '#9aa7c3', marginBottom: '4px' }}>Deny</div>
                    <div style={{ fontSize: '18px', color: '#f76363', fontWeight: 'bold' }}>{analysis.deny}</div>
                  </div>
                  <div style={{ background: '#2d3748', padding: '12px', borderRadius: '6px', textAlign: 'center' }}>
                    <div style={{ fontSize: '12px', color: '#9aa7c3', marginBottom: '4px' }}>Wildcard Actions</div>
                    <div style={{ fontSize: '18px', color: '#fff', fontWeight: 'bold' }}>{analysis.wildActions}</div>
                  </div>
                  <div style={{ background: '#2d3748', padding: '12px', borderRadius: '6px', textAlign: 'center' }}>
                    <div style={{ fontSize: '12px', color: '#9aa7c3', marginBottom: '4px' }}>Wildcard Resources</div>
                    <div style={{ fontSize: '18px', color: '#fff', fontWeight: 'bold' }}>{analysis.wildResources}</div>
                  </div>
                  <div style={{ background: '#2d3748', padding: '12px', borderRadius: '6px', textAlign: 'center' }}>
                    <div style={{ fontSize: '12px', color: '#9aa7c3', marginBottom: '4px' }}>No Conditions</div>
                    <div style={{ fontSize: '18px', color: '#fff', fontWeight: 'bold' }}>{analysis.noConditions}</div>
                  </div>
                </div>
                <label style={{ display: 'block', fontSize: '12px', color: '#9aa7c3', marginBottom: '12px' }}>
                  Policy type
                  <select
                    value={typeChoice}
                    onChange={e => setTypeChoice(e.target.value as PolicyType | 'auto')}
                    style={{ display: 'block', marginTop: '4px', padding: '4px 6px', background: '#0a1430', color: '#eaeef7', border: '1px solid #4a5568', borderRadius: '4px', fontSize: '13px' }}
                  >
                    <option value="auto">Detected: {POLICY_TYPES.find(t => t.value === detectedType)?.label}</option>
                    {POLICY_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                  </select>
                </label>
                {(() => {
                  const size = sizeLimit(policyType)
                  return (
                    <div style={{ fontSize: '12px', color: size && parsed.charCount > size.limit ? '#ffb86b' : '#9aa7c3', marginBottom: '12px' }}>
                      {size
                        ? <>Size: {parsed.charCount.toLocaleString('en-US')} of {size.limit.toLocaleString('en-US')} characters ({size.label}, counted as compact JSON)</>
                        : <>Size: {parsed.charCount.toLocaleString('en-US')} characters as compact JSON. Limits for resource-based policies vary by service.</>}
                    </div>
                  )
                })()}
                <label style={{ display: 'block', fontSize: '12px', color: '#9aa7c3', marginBottom: '12px' }}>
                  Your AWS account ID (optional, used only in this page to flag cross-account principals)
                  <input
                    value={accountId}
                    type={redactor ? 'password' : 'text'}
                    onChange={e => setAccountId(e.target.value.trim())}
                    placeholder="12-digit account ID"
                    inputMode="numeric"
                    maxLength={12}
                    aria-invalid={accountId !== '' && !accountValid}
                    style={{ display: 'block', marginTop: '4px', width: '160px', padding: '4px 6px', background: '#0a1430', color: '#eaeef7', border: '1px solid #4a5568', borderRadius: '4px', fontSize: '13px' }}
                  />
                  {accountId !== '' && !accountValid && <span style={{ color: '#f76363' }}>Enter exactly 12 digits.</span>}
                </label>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <h4 style={{ margin: 0, color: '#fff', fontSize: '14px' }}>Findings</h4>
                  <button className="btn secondary" style={{ fontSize: '12px', padding: '4px 10px' }} onClick={copyMarkdown}>Copy as Markdown</button>
                </div>
                {copyStatus && <div role="status" style={{ fontSize: '12px', color: '#5bb8ff', marginBottom: '6px' }}>{copyStatus}</div>}
                {copyFallback && <textarea aria-label="Findings as Markdown" readOnly value={copyFallback} onFocus={e => e.currentTarget.select()} style={{ minHeight: '120px', marginBottom: '8px' }} />}
                {(() => {
                  const notice = guardrailNotice(policyType, typeChoice === 'auto')
                  return notice && <div role="note" data-testid="guardrail-notice" style={{ fontSize: '12px', color: '#ffd9a8', border: '1px solid #ffb86b', borderRadius: '6px', padding: '8px 10px', marginBottom: '8px' }}>{notice}</div>
                })()}
                <FindingsList findings={analysis.findings} tx={tx} />
                <p style={{ fontSize: '12px', color: '#9aa7c3', margin: '10px 0 0 0' }}>
                  These checks run offline and cover common mistakes only. They do not replace IAM Access Analyzer policy validation.
                </p>
              </>
            )}

            {activeTab === 'readable' && (
              <>
                <h3 style={{ margin: '0 0 16px 0', color: '#fff', fontSize: '16px' }}>Human Readable Translation</h3>
                {isGuardrail(policyType) && (
                  <div role="note" style={{ fontSize: '12px', color: '#ffd9a8', marginBottom: '12px' }}>
                    {policyType === 'scp' ? 'SCPs and RCPs' : 'Permissions boundaries'} only set the maximum permissions.
                    &quot;Allowed&quot; below means not blocked by this policy; access still has to be granted by an identity or resource-based policy.
                  </div>
                )}
                <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                  {(displayParsed ?? parsed).statements.map((statement, index) => (
                    <div
                      key={statement.id}
                      style={{
                        background: '#2d3748',
                        padding: '16px',
                        marginBottom: '12px',
                        borderRadius: '6px',
                        borderLeft: `4px solid ${statement.effect === 'Allow' ? '#29c26b' : '#f76363'}`
                      }}
                    >
                      <h4 style={{ margin: '0 0 12px 0', color: '#fff', fontSize: '14px' }}>
                        Statement {index + 1} {statement.sid && `(${statement.sid})`}
                      </h4>
                      <div style={{ color: '#e2e8f0', fontSize: '13px', lineHeight: '1.5' }}>
                        <TranslatedStatement statement={statement} />
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}

            {activeTab === 'optimize' && (
              <>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                  <h3 style={{ margin: 0, color: '#fff', fontSize: '16px' }}>Policy Optimization</h3>
                  <button
                    onClick={downloadOptimizedPolicy}
                    disabled={!permissions.some(p => p.status === 'needed')}
                    title={redactor ? 'Downloads the real policy values, not the redacted view' : undefined}
                    style={{
                      padding: '8px 16px',
                      background: '#29c26b',
                      color: '#fff',
                      border: 'none',
                      borderRadius: '4px',
                      cursor: 'pointer',
                      fontSize: '13px',
                      opacity: permissions.some(p => p.status === 'needed') ? 1 : 0.5
                    }}
                  >
                    Download Optimized Policy
                  </button>
                </div>
                <div role="note" style={{ border: '1px solid #ffb86b', background: '#3a2f1f', color: '#ffd9a8', borderRadius: '6px', padding: '8px 10px', fontSize: '12px', marginBottom: '12px' }}>
                  <strong>Review before use.</strong> This is a starting point, not a validated policy. Within a statement,
                  every kept action applies to every kept resource, so the result can allow more than the exact rows you
                  mark Needed. Validate it with IAM Access Analyzer policy validation before you attach it.
                </div>
                {oldVersion && (
                  <p data-testid="optimize-version-warning" style={{ fontSize: '12px', color: '#ffb86b', margin: '0 0 12px 0' }}>{oldVersion}</p>
                )}
                {redactor && (
                  <p data-testid="download-not-redacted" style={{ fontSize: '12px', color: '#ffb86b', margin: '0 0 12px 0' }}>
                    The downloaded file contains the real policy values, not the redacted view, so it can be used as a policy.
                  </p>
                )}
                <p style={{ fontSize: '12px', color: '#9aa7c3', margin: '0 0 12px 0' }}>
                  Allow statements keep only the rows marked Needed; their conditions and principals are kept.
                  Deny statements and statements using NotAction or NotResource are kept as written.
                </p>
                <div style={{ maxHeight: '400px', overflowY: 'auto', background: '#2d3748', borderRadius: '6px' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                    <thead>
                      <tr style={{ background: '#4a5568' }}>
                        <th style={{ padding: '8px', textAlign: 'left', color: '#fff', borderBottom: '1px solid #718096' }}>Statement</th>
                        <th style={{ padding: '8px', textAlign: 'left', color: '#fff', borderBottom: '1px solid #718096' }}>Action</th>
                        <th style={{ padding: '8px', textAlign: 'left', color: '#fff', borderBottom: '1px solid #718096' }}>Resource</th>
                        <th style={{ padding: '8px', textAlign: 'left', color: '#fff', borderBottom: '1px solid #718096' }}>Effect</th>
                        <th style={{ padding: '8px', textAlign: 'left', color: '#fff', borderBottom: '1px solid #718096' }}>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {permissions.map((perm, index) => (
                        <tr
                          key={index}
                          style={{
                            background: perm.status === 'needed' ? '#2d5a2d' : perm.status === 'not-needed' ? '#5a2d2d' : 'transparent',
                            borderBottom: '1px solid #4a5568'
                          }}
                        >
                          <td style={{ padding: '8px', color: '#e2e8f0' }}>Statement {perm.statementIndex}</td>
                          <td style={{ padding: '8px', color: '#e2e8f0', wordBreak: 'break-all' }}>{tx(perm.action)}</td>
                          <td style={{ padding: '8px', color: '#e2e8f0', wordBreak: 'break-all' }}>{tx(perm.resource)}</td>
                          <td style={{ padding: '8px', color: perm.effect === 'Allow' ? '#29c26b' : '#f76363' }}>{perm.effect}</td>
                          <td style={{ padding: '8px' }}>
                            {perm.locked ? (
                              <span title={perm.locked} style={{ color: '#9aa7c3', fontSize: '12px' }}>Kept as written</span>
                            ) : (
                            <select
                              value={perm.status}
                              onChange={(e) => updatePermissionStatus(index, e.target.value as PermissionStatus)}
                              style={{
                                background: '#4a5568',
                                color: '#fff',
                                border: '1px solid #718096',
                                borderRadius: '4px',
                                padding: '4px',
                                fontSize: '12px'
                              }}
                            >
                              <option value="unknown">Unknown</option>
                              <option value="needed">Needed</option>
                              <option value="not-needed">Not Needed</option>
                            </select>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {permissionTotal > permissions.length && (
                  <p style={{ fontSize: '12px', color: '#ffb86b', margin: '8px 0 0 0' }}>
                    Showing the first {permissions.length.toLocaleString('en-US')} of {permissionTotal.toLocaleString('en-US')} rows.
                    Rows not shown stay Unknown, so they are left out of the optimized policy.
                  </p>
                )}
              </>
            )}

            {activeTab === 'compare' && <CompareTab after={parsed} options={options} redactor={redactor} />}

            {activeTab === 'check' && <CheckAccessTab parsed={parsed} policyType={policyType} tx={tx} redacted={!!redactor} />}
          </div>
        </>
      )}
    </div>
  )
}
