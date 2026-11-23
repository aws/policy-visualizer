// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { ParsedPolicy, ParsedStatement } from './types'
import type { Finding } from './findings'
import { STATEMENT_ELEMENTS } from './parse'

// Element lists pool every statement, so a value that moves between statements shows up in the
// statement list. This compares text, not effective permissions.

export interface ElementDiff {
  added: string[]
  removed: string[]
}

export interface PolicyDiff {
  // Ignores Sid, statement order, and value order within an element.
  statements: ElementDiff
  allowActions: ElementDiff
  denyActions: ElementDiff
  allowResources: ElementDiff
  denyResources: ElementDiff
  principals: ElementDiff
  conditions: ElementDiff
  sids: ElementDiff
  statementCount: { before: number; after: number }
  version: { before?: string; after?: string }
  newFindings: Finding[]
  resolvedFindings: Finding[]
}

function collect(p: ParsedPolicy, effect: 'Allow' | 'Deny', pick: (s: ParsedStatement) => string[]) {
  return new Set(p.statements.filter(s => s.effect === effect).flatMap(pick))
}

function diffSets(before: Set<string>, after: Set<string>): ElementDiff {
  return {
    added: [...after].filter(v => !before.has(v)).sort(),
    removed: [...before].filter(v => !after.has(v)).sort(),
  }
}

const actionsOf = (s: ParsedStatement) => s.actions.map(a => (s.notAction ? `NotAction ${a}` : a))
const resourcesOf = (s: ParsedStatement) => s.resources.map(r => (s.notResource ? `NotResource ${r}` : r))
const principalsOf = (s: ParsedStatement) => s.principals.map(p => `${s.effect} ${s.notPrincipal ? 'NotPrincipal ' : ''}${p}`)
const conditionsOf = (s: ParsedStatement) => s.conditions.map(c => `${s.effect} ${c.operator} ${c.key}: ${c.values.join(', ')}`)

const sorted = (values: string[]) => [...new Set(values)].sort()

const element = (st: ParsedStatement, name: 'Action' | 'Resource' | 'Principal') =>
  st.raw[name] !== undefined ? name : st.raw[`Not${name}`] !== undefined ? `Not${name}` : ''

// Values are sorted, so order doesn't matter; elements outside IAM's grammar are kept as written.
function statementKey(st: ParsedStatement): string {
  const conditions = sorted(st.conditions.map(c => JSON.stringify([c.operator, c.key, sorted(c.values)])))
  const unknown = Object.keys(st.raw).filter(k => !STATEMENT_ELEMENTS.includes(k)).sort()
    .map(k => [k, JSON.stringify(st.raw[k])])
  return JSON.stringify([st.effect,
    element(st, 'Action'), sorted(st.actions),
    element(st, 'Resource'), sorted(st.resources),
    element(st, 'Principal'), sorted(st.principals),
    conditions, unknown])
}

// Values as written in the policy, so redaction finds them.
function statementLabel(st: ParsedStatement): string {
  const parts: string[] = [st.effect]
  const add = (name: string, values: string[]) => { if (name) parts.push(`${name}: ${sorted(values).join(', ')}`) }
  add(element(st, 'Principal'), st.principals)
  add(element(st, 'Action'), st.actions)
  add(element(st, 'Resource'), st.resources)
  for (const c of st.conditions) parts.push(`Condition ${c.operator} ${c.key}: ${sorted(c.values).join(', ')}`)
  for (const k of Object.keys(st.raw).filter(k => !STATEMENT_ELEMENTS.includes(k)).sort()) parts.push(k)
  return parts.join('; ')
}

function unmatched(from: ParsedStatement[], to: ParsedStatement[]): string[] {
  const left = new Map<string, number>()
  for (const st of to) { const k = statementKey(st); left.set(k, (left.get(k) ?? 0) + 1) }
  const out: string[] = []
  for (const st of from) {
    const k = statementKey(st)
    const n = left.get(k) ?? 0
    if (n) left.set(k, n - 1)
    else out.push(statementLabel(st))
  }
  return sorted(out)
}

// Findings match by statement content, not number, so reordering alone isn't a change.
function findingKeys(p: ParsedPolicy) {
  const keys = p.statements.map(statementKey)
  return (f: Finding) => JSON.stringify([f.code, f.detail, f.statement ? keys[f.statement - 1] ?? f.statement : ''])
}

export function diffPolicies(before: ParsedPolicy, after: ParsedPolicy, beforeFindings: Finding[], afterFindings: Finding[]): PolicyDiff {
  const both = (pick: (s: ParsedStatement) => string[]) =>
    diffSets(new Set(before.statements.flatMap(pick)), new Set(after.statements.flatMap(pick)))
  const beforeKey = findingKeys(before)
  const afterKey = findingKeys(after)
  const beforeKeys = new Set(beforeFindings.map(beforeKey))
  const afterKeys = new Set(afterFindings.map(afterKey))
  return {
    statements: { added: unmatched(after.statements, before.statements), removed: unmatched(before.statements, after.statements) },
    allowActions: diffSets(collect(before, 'Allow', actionsOf), collect(after, 'Allow', actionsOf)),
    denyActions: diffSets(collect(before, 'Deny', actionsOf), collect(after, 'Deny', actionsOf)),
    allowResources: diffSets(collect(before, 'Allow', resourcesOf), collect(after, 'Allow', resourcesOf)),
    denyResources: diffSets(collect(before, 'Deny', resourcesOf), collect(after, 'Deny', resourcesOf)),
    principals: both(principalsOf),
    conditions: both(conditionsOf),
    sids: both(s => (s.sid ? [s.sid] : [])),
    statementCount: { before: before.statements.length, after: after.statements.length },
    version: { before: before.version, after: after.version },
    newFindings: afterFindings.filter(f => !beforeKeys.has(afterKey(f))),
    resolvedFindings: beforeFindings.filter(f => !afterKeys.has(beforeKey(f))),
  }
}

export function hasChanges(d: PolicyDiff) {
  const sets = [d.statements, d.allowActions, d.denyActions, d.allowResources, d.denyResources, d.principals, d.conditions, d.sids]
  return sets.some(s => s.added.length || s.removed.length) ||
    d.statementCount.before !== d.statementCount.after ||
    d.version.before !== d.version.after ||
    d.newFindings.length > 0 || d.resolvedFindings.length > 0
}
