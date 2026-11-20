// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { ParsedPolicy, ParsedStatement, Statement } from './types'

// Answer "does this one policy allow this request?" by matching the action,
// resource, and principal against each statement, with an explicit Deny
// winning over any Allow. It does NOT evaluate conditions (it reports that
// they apply), other policies (identity, resource, SCPs, RCPs, boundaries,
// session policies), or service-specific rules. It is a reading aid, not an
// authorization decision.

export interface AccessRequest {
  action: string
  resource?: string
  principal?: string
}

export type Match = 'yes' | 'no' | 'unknown'

export interface StatementMatch {
  statement: number
  sid?: string
  effect: 'Allow' | 'Deny'
  match: Match
  // True when the statement applies only for some requests: it has
  // conditions, or its Resource match depends on a policy variable.
  conditional: boolean
  variables: boolean
  // For match 'unknown': what the request didn't say that this statement needs.
  needs: ('resource' | 'principal')[]
  notes: string[]
}

export type Decision = 'explicit-deny' | 'allowed' | 'conditional' | 'depends-on-principal' | 'depends-on-resource' | 'implicit-deny'

export interface AccessResult {
  decision: Decision
  summary: string
  matches: StatementMatch[]
}

// IAM-style wildcard match: "*" matches any run of characters, "?" exactly
// one. Two pointers that remember the last "*", so the cost is at most
// pattern length x text length. A regex built from the pattern (".*" per
// "*") can backtrack exponentially on patterns like "*a*a*a...b", which
// would let a crafted policy freeze the page.
export function wildcardMatch(pattern: string, text: string, ignoreCase = false): boolean {
  const p = ignoreCase ? pattern.toLowerCase() : pattern
  const t = ignoreCase ? text.toLowerCase() : text
  let pi = 0, ti = 0, star = -1, mark = 0
  while (ti < t.length) {
    if (pi < p.length && (p[pi] === '?' || p[pi] === t[ti])) {
      pi++; ti++
    } else if (pi < p.length && p[pi] === '*') {
      star = pi++
      mark = ti
    } else if (star !== -1) {
      pi = star + 1
      ti = ++mark
    } else {
      return false
    }
  }
  while (pi < p.length && p[pi] === '*') pi++
  return pi === p.length
}

const actionMatches = (pattern: string, action: string) => wildcardMatch(pattern, action, true)

// A Resource pattern as a list of literal characters and wildcards, so an
// escaped "*" can be told apart from a real one.
const STAR = 0, ONE = 1
type Glob = (string | typeof STAR | typeof ONE)[]

// Same two-pointer matcher as wildcardMatch, over a compiled pattern.
function globMatch(p: Glob, t: string): boolean {
  let pi = 0, ti = 0, star = -1, mark = 0
  while (ti < t.length) {
    if (pi < p.length && (p[pi] === ONE || p[pi] === t[ti])) {
      pi++; ti++
    } else if (pi < p.length && p[pi] === STAR) {
      star = pi++
      mark = ti
    } else if (star !== -1) {
      pi = star + 1
      ti = ++mark
    } else {
      return false
    }
  }
  while (pi < p.length && p[pi] === STAR) pi++
  return pi === p.length
}

// "*" and "?" are wildcards. With variables on (Version 2012-10-17),
// ${*}, ${?}, and ${$} are IAM's escapes for those literal characters, and
// any other ${...} is a policy variable whose value comes from the request,
// so it is matched as "*" and reported. With variables off, ${...} is plain
// text and only "literalBraces" decides whether a "*" or "?" inside it is a
// wildcard.
function compileResource(pattern: string, variables: boolean, literalBraces = false): { glob: Glob; usesVariable: boolean } {
  const glob: Glob = []
  let usesVariable = false
  // The next "}", or -1 once none follows, so many "${" without a "}" cost
  // one search in total instead of one each.
  let close = -2
  for (let i = 0; i < pattern.length;) {
    let end = -1
    if (close !== -1 && pattern.startsWith('${', i)) {
      if (close < i + 2) close = pattern.indexOf('}', i + 2)
      end = close
    }
    if (end !== -1 && variables) {
      const name = pattern.slice(i + 2, end)
      if (name === '*' || name === '?' || name === '$') glob.push(name)
      else { glob.push(STAR); usesVariable = true }
      i = end + 1
    } else if (end !== -1 && literalBraces) {
      glob.push(...pattern.slice(i, end + 1))
      i = end + 1
    } else {
      const c = pattern[i++]
      glob.push(c === '*' ? STAR : c === '?' ? ONE : c)
    }
  }
  return { glob, usesVariable }
}

// The text with every ${...} removed, as a linear scan (a regex such as
// /\$\{[^}]*\}/g rescans to the end for each unclosed "${").
export function stripVariables(text: string): string {
  let out = ''
  let start = 0
  let close = -2
  for (let i = text.indexOf('${'); i !== -1 && close !== -1; i = text.indexOf('${', i + 1)) {
    if (i < start) continue
    if (close < i + 2) close = text.indexOf('}', i + 2)
    if (close === -1) break
    out += text.slice(start, i)
    start = close + 1
  }
  return out + text.slice(start)
}

// 'maybe' means it matches only for some requests: a policy variable has to
// resolve to a value that fits.
type ResourceMatch = 'yes' | 'no' | 'maybe'

function resourceMatches(pattern: string, resource: string, variables: boolean): ResourceMatch {
  if (!pattern.includes('${')) return wildcardMatch(pattern, resource) ? 'yes' : 'no'
  if (variables) {
    const { glob, usesVariable } = compileResource(pattern, true)
    if (!globMatch(glob, resource)) return 'no'
    return usesVariable ? 'maybe' : 'yes'
  }
  // Without Version 2012-10-17, ${...} is plain text. Whether a "*" or "?"
  // inside it is still a wildcard is not certain, so a match that needs it
  // to be one is only a 'maybe'.
  if (globMatch(compileResource(pattern, false, true).glob, resource)) return 'yes'
  return globMatch(compileResource(pattern, false).glob, resource) ? 'maybe' : 'no'
}

function accountOf(v: string): string | null {
  if (/^\d{12}$/.test(v)) return v
  return /^arn:aws[a-z-]*:(?:iam|sts)::(\d{12}):/.exec(v)?.[1] ?? null
}

type Entry = { type: string; value: string }
function entries(p: Statement['Principal']): Entry[] {
  if (!p) return []
  if (typeof p === 'string') return [{ type: '*', value: p }]
  if (Array.isArray(p)) return p.map(value => ({ type: 'AWS', value }))
  return Object.entries(p).flatMap(([type, v]) => (Array.isArray(v) ? v : [v]).map(value => ({ type, value })))
}

// Is the caller a session of this role? A role session ARN,
// arn:aws:sts::111122223333:assumed-role/<role-name>/<session-name>, has the
// role's partition, account, and name, but not its path.
function isSessionOf(roleArn: string, caller: string): boolean {
  const role = /^arn:(aws[a-z-]*):iam::(\d{12}):role\//.exec(roleArn)
  const session = /^arn:(aws[a-z-]*):sts::(\d{12}):assumed-role\/([^/]+)\/[^/]+$/.exec(caller)
  if (!role || !session) return false
  const name = roleArn.slice(roleArn.lastIndexOf('/') + 1)
  return role[1] === session[1] && role[2] === session[2] && name === session[3]
}

// Does the caller match one principal entry? Account principals
// (111122223333 or arn:aws:iam::111122223333:root) match any principal in
// that account, which then also needs its own identity policy to allow it.
// A role ARN in Principal matches the sessions of that role. In NotPrincipal
// that is not certain: IAM may check the account, the role, and the session
// in turn, so a role session against a role ARN there is 'unknown'.
function principalMatches(e: Entry, caller: string, notes: string[], inNotPrincipal = false): Match {
  if (e.value === '*') return 'yes'
  if (e.type === 'Service' || e.type === 'Federated' || e.type === 'CanonicalUser') return e.value.toLowerCase() === caller.toLowerCase() ? 'yes' : 'no'
  const acct = /^\d{12}$/.test(e.value) ? e.value : /^arn:aws[a-z-]*:iam::(\d{12}):root$/.exec(e.value)?.[1]
  if (acct) {
    const ok = accountOf(caller) === acct
    if (ok) notes.push(`Matches account ${acct}; the caller also needs an identity policy in that account that allows it.`)
    return ok ? 'yes' : 'no'
  }
  if (e.value === caller) return 'yes'
  if (!isSessionOf(e.value, caller)) return 'no'
  notes.push(inNotPrincipal
    ? `The caller is a session of ${e.value}, which NotPrincipal names. Whether that excludes the session is not certain, so this statement may apply.`
    : `Matches ${e.value}: the caller is a session of that role.`)
  return inNotPrincipal ? 'unknown' : 'yes'
}

function matchStatement(st: ParsedStatement, n: number, req: AccessRequest, variables: boolean): StatementMatch {
  const notes: string[] = []
  const needs: ('resource' | 'principal')[] = []
  let match: Match = 'yes'
  let dependsOnVariable = false

  const hitAction = st.actions.some(a => actionMatches(a, req.action))
  if (st.notAction ? hitAction : !hitAction) match = 'no'

  if (match === 'yes' && st.resources.length) {
    if (req.resource) {
      const hits = st.resources.map(r => resourceMatches(r, req.resource as string, variables))
      const hit = hits.includes('yes')
      // A 'maybe' match makes Resource apply for some requests, and so
      // NotResource not apply for those same requests.
      const maybe = !hit && hits.includes('maybe')
      if (st.notResource ? hit : !hit && !maybe) match = 'no'
      else if (maybe) {
        dependsOnVariable = true
        notes.push(st.notResource
          ? 'NotResource uses policy variables: the statement applies only if they resolve to values that do not match this resource.'
          : 'Resource uses policy variables: the statement applies only if they resolve to values that match this resource.')
      }
      if (!variables && st.resources.some(r => r.includes('${'))) {
        notes.push('The policy Version is not 2012-10-17, so ${...} in Resource is plain text, not a policy variable.')
      }
    } else if (!(st.resources.includes('*') && !st.notResource)) {
      // Scoped to specific resources: whether it applies depends on which.
      match = 'unknown'
      needs.push('resource')
      notes.push('Applies only to specific resources: enter a resource ARN to check.')
    }
  }

  const principals = entries(st.raw.Principal)
  const notPrincipals = entries(st.raw.NotPrincipal)
  if (match !== 'no' && (principals.length || notPrincipals.length)) {
    if (!req.principal) {
      match = 'unknown'
      needs.push('principal')
      notes.push('Applies only to specific principals: enter the caller to check.')
    } else if (principals.length) {
      if (!principals.some(e => principalMatches(e, req.principal as string, notes) === 'yes')) match = 'no'
    } else {
      const hits = notPrincipals.map(e => principalMatches(e, req.principal as string, notes, true))
      if (hits.includes('yes')) match = 'no'
      else if (hits.includes('unknown')) {
        match = 'unknown'
        needs.push('principal')
      }
    }
  }

  if (match !== 'no' && st.conditions.length) notes.push(`Applies only if its conditions are met: ${st.conditions.map(c => `${c.operator} ${c.key}`).join('; ')}.`)
  const conditional = st.conditions.length > 0 || dependsOnVariable
  return { statement: n, sid: st.sid, effect: st.effect, match, conditional, variables: dependsOnVariable, needs, notes }
}

const label = (m: StatementMatch) => `Statement ${m.statement}${m.sid ? ` (${m.sid})` : ''}`

export function evaluateAccess(parsed: ParsedPolicy, req: AccessRequest): AccessResult {
  // Policy variables exist only in Version 2012-10-17.
  const variables = parsed.version === '2012-10-17'
  const matches = parsed.statements.map((st, i) => matchStatement(st, i + 1, req, variables))
  const hit = matches.filter(m => m.match === 'yes')
  const denyHard = hit.find(m => m.effect === 'Deny' && !m.conditional)
  const denySoft = hit.filter(m => m.effect === 'Deny' && m.conditional)
  const allowHard = hit.find(m => m.effect === 'Allow' && !m.conditional)
  const allowSoft = hit.filter(m => m.effect === 'Allow' && m.conditional)
  const unknown = matches.filter(m => m.match === 'unknown')

  if (denyHard) return { decision: 'explicit-deny', summary: `Explicitly denied by ${label(denyHard)}.`, matches }
  // A Deny that might still apply (conditions, a policy variable, or a
  // principal we couldn't check) qualifies any Allow answer.
  const maybeDeny = [...denySoft, ...unknown.filter(m => m.effect === 'Deny')]
  const unless = maybeDeny.length ? ` unless ${maybeDeny.map(label).join(', ')} denies it` : ''
  if (allowHard) {
    return { decision: maybeDeny.length ? 'conditional' : 'allowed', summary: `Allowed by ${label(allowHard)}${unless}.`, matches }
  }
  if (allowSoft.length) {
    const names = allowSoft.map(label).join(', ')
    const conds = allowSoft.some(m => parsed.statements[m.statement - 1].conditions.length)
    const what = !allowSoft.some(m => m.variables) ? `the conditions in ${names} are met`
      : `the ${conds ? 'conditions and policy variables' : 'policy variables'} in ${names} match the request`
    return { decision: 'conditional', summary: `Allowed only if ${what}${unless}.`, matches }
  }
  // Only an unresolved Allow can make the answer "it depends". An unresolved
  // Deny with no Allow still leaves the request implicitly denied.
  const unknownAllow = unknown.filter(m => m.effect === 'Allow')
  if (unknownAllow.length) {
    const byResource = unknownAllow.filter(m => m.needs.includes('resource'))
    if (byResource.length) {
      return { decision: 'depends-on-resource', summary: `Depends on the resource: ${byResource.map(label).join(', ')} apply only to specific resources. Enter a resource ARN to check.`, matches }
    }
    return { decision: 'depends-on-principal', summary: `Depends on the caller: ${unknownAllow.map(label).join(', ')} apply only to specific principals.`, matches }
  }
  return { decision: 'implicit-deny', summary: 'Not allowed by this policy: no statement allows it (implicit deny).', matches }
}
