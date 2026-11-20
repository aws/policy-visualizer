// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { ParsedPolicy, ParsedStatement, Statement } from './types'

// Tables render at most this many rows; more would make the page sluggish.
export const MAX_TABLE_ROWS = 2000

// Table placeholder for a statement with no Action or no Resource list.
export const NONE = '(none)'

export type PermissionStatus = 'needed' | 'not-needed' | 'unknown'

export interface PermissionRow {
  statementId: string
  statementIndex: number
  action: string
  resource: string
  effect: string
  status: PermissionStatus
  // Set when the statement can't be narrowed safely. The statement is then
  // written to the optimized policy exactly as it was, and this explains why.
  locked?: string
}

// Table rows for one statement: one per action and resource pair, with a
// missing list counted as one "(none)" entry.
export function pairCount(st: ParsedStatement): number {
  return Math.max(st.actions.length, 1) * Math.max(st.resources.length, 1)
}

// Total rows for the whole policy, by arithmetic. Building every row first
// would take actions x resources memory, which a crafted policy can push to
// tens of millions of rows within the input size limit.
export function permissionRowCount(parsed: ParsedPolicy): number {
  return parsed.statements.reduce((n, st) => n + pairCount(st), 0)
}

// Why a statement must be kept exactly as written, or undefined if it is safe
// to narrow by dropping actions and resources.
export function lockReason(st: ParsedStatement): string | undefined {
  if (st.effect === 'Deny') {
    return 'Deny statements are kept as written. Removing parts of a Deny would grant more access.'
  }
  if (st.notAction || st.notResource) {
    return 'NotAction and NotResource mean "everything except". Removing entries would grant more access, so the statement is kept as written.'
  }
  if (!st.actions.length || !st.resources.length) {
    return 'The statement has no Action or Resource list to narrow, so it is kept as written.'
  }
  // Its rows can't all be shown, so the user can't mark them all.
  if (pairCount(st) > MAX_TABLE_ROWS) {
    return `The statement has ${pairCount(st).toLocaleString('en-US')} action and resource pairs, more than the table can show (${MAX_TABLE_ROWS.toLocaleString('en-US')}), so it is kept as written.`
  }
  return undefined
}

// The first `limit` rows only; use permissionRowCount for the total.
export function buildPermissionRows(parsed: ParsedPolicy, limit = MAX_TABLE_ROWS): PermissionRow[] {
  const rows: PermissionRow[] = []
  parsed.statements.forEach((st, idx) => {
    if (rows.length >= limit) return
    const locked = lockReason(st)
    // A missing list is shown as "(none)", never as "*", which would read
    // as a wildcard grant.
    const actions = st.actions.length ? st.actions : [NONE]
    const resources = st.resources.length ? st.resources : [NONE]
    for (const action of actions) {
      for (const resource of resources) {
        if (rows.length >= limit) return
        rows.push({
          statementId: st.id,
          statementIndex: idx + 1,
          action: st.notAction ? `NotAction: ${action}` : action,
          resource: st.notResource ? `NotResource: ${resource}` : resource,
          effect: st.effect,
          status: 'unknown',
          locked
        })
      }
    }
  })
  return rows
}

export interface SummaryRow {
  stmt: string
  effect: string
  action: string
  resource: string
  condition: string
}

// Rows for the Policy Summary table: the first `limit` only, plus the total.
export function buildSummaryRows(parsed: ParsedPolicy, limit = MAX_TABLE_ROWS): { rows: SummaryRow[]; total: number } {
  const rows: SummaryRow[] = []
  for (const s of parsed.statements) {
    if (rows.length >= limit) break
    const actions = s.actions.length ? s.actions : [NONE]
    const resources = s.resources.length ? s.resources : [NONE]
    const condition = s.conditions.length ? s.conditions.map(c => `${c.operator} ${c.key}: ${c.values.join(', ')}`).join('; ') : 'None'
    for (const a of actions) {
      for (const r of resources) {
        if (rows.length >= limit) break
        rows.push({
          stmt: s.id,
          effect: s.effect,
          action: s.notAction ? `NotAction: ${a}` : a,
          resource: s.notResource ? `NotResource: ${r}` : r,
          condition,
        })
      }
    }
  }
  return { rows, total: permissionRowCount(parsed) }
}

function oneOrMany(values: string[]): string | string[] {
  return values.length === 1 ? values[0] : values
}

// Build a narrowed policy from the rows the user marked "needed".
//
// The result never grants more than the original:
// - Narrowable Allow statements keep only the actions and resources from
//   rows marked "needed". Every other element (Sid, Principal, NotPrincipal,
//   Condition) is copied unchanged. Statements with nothing needed are dropped.
// - Locked statements (Deny, NotAction/NotResource, no Action or Resource
//   list, too many rows to show) are copied exactly as written.
// - Version is copied as written, and left out if the input had none. A
//   missing Version means 2008-10-17, where ${aws:username} is plain text;
//   adding 2012-10-17 would turn it into a variable and match more.
export function buildOptimizedPolicy(parsed: ParsedPolicy, rows: PermissionRow[]): { Version?: string; Id?: string; Statement: Statement[] } {
  const statements: Statement[] = []
  for (const st of parsed.statements) {
    if (lockReason(st)) {
      statements.push(st.raw)
      continue
    }
    const needed = rows.filter(r => r.statementId === st.id && r.status === 'needed')
    if (!needed.length) continue
    const actions = st.actions.filter(a => needed.some(r => r.action === a))
    const resources = st.resources.filter(res => needed.some(r => r.resource === res))
    statements.push({ ...st.raw, Action: oneOrMany(actions), Resource: oneOrMany(resources) })
  }
  return {
    ...(parsed.version !== undefined ? { Version: parsed.version } : {}),
    ...(parsed.policyId ? { Id: parsed.policyId } : {}),
    Statement: statements
  }
}

// Shown in the Optimize view when the policy's Version makes "${...}" plain
// text. The optimized policy keeps that Version, so it matches the same
// resources; switching to 2012-10-17 is the user's call.
export function versionWarning(parsed: ParsedPolicy): string | undefined {
  if (parsed.version !== undefined && parsed.version !== '2008-10-17') return undefined
  if (!parsed.statements.some(s => JSON.stringify(s.raw).includes('${'))) return undefined
  const which = parsed.version ? `Version ${parsed.version}` : 'no Version (treated as 2008-10-17)'
  return `This policy has ${which}, so text such as \${aws:username} is matched literally, not as a policy variable. The optimized policy keeps the same Version. Changing it to 2012-10-17 would turn that text into variables, which can grant more access.`
}
