// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { ParsedPolicy, ParsedStatement } from './types'
import type { Finding } from './findings'
import { STATEMENT_ELEMENTS } from './parse'

// Compare two versions of a policy statement by statement and element by
// element: which statements, actions, resources, principals, and conditions
// were added or removed, per effect. The element lists pool every
// statement, so a change that only moves an action, principal, or condition
// to another statement shows up in the statement list. This shows what
// changed in the text; it does not evaluate effective permissions (a new
// wildcard can make an existing entry redundant, for example).

export interface ElementDiff {
  added: string[]
  removed: string[]
}

export interface PolicyDiff {
  // Statements that are not in the other version, ignoring Sid, statement
  // order, and the order of values within an element.
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

// Which of the two elements a statement uses, if any.
const element = (st: ParsedStatement, name: 'Action' | 'Resource' | 'Principal') =>
  st.raw[name] !== undefined ? name : st.raw[`Not${name}`] !== undefined ? `Not${name}` : ''

// Everything a statement says except its Sid, as a string that is the same
// for two statements exactly when they say the same thing. Values are
// sorted, so their order doesn't matter. Elements outside IAM's grammar are
// included as written.
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

// A statement in plain text for the list of changed statements. Values are
// written as they appear in the policy so that redaction finds them.
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

// Statements of `from` with no identical statement left in `to`, counting
// duplicates.
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

// Findings match on what they say and on the statement they are about, by
// its content rather than its number, so reordering statements doesn't show
// up as a change but a finding that moves to another statement does.
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
