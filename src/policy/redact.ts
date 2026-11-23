// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { ParsedPolicy, ParsedStatement } from './types'
import { POLICY_ELEMENTS, STATEMENT_ELEMENTS } from './parse'

// Replace identifying values with stable placeholders (ACCOUNT-1, BUCKET-1, SID-1, VALUE-1).

const AWS_REGION = /^(us|eu|ap|ca|sa|af|me|il|mx|cn)(-(gov|iso[a-z]?))?-[a-z]+-\d$/

const PUBLIC_IDPS = /^(cognito-identity\.amazonaws\.com|accounts\.google\.com|graph\.facebook\.com|www\.amazon\.com)$/

const ELEMENT_NAMES = new Set([...POLICY_ELEMENTS, ...STATEMENT_ELEMENTS])

// The character classes don't overlap, so the match is linear.
const VARIABLE = /^(?:[*?$]|([A-Za-z0-9-]+|cognito-identity\.amazonaws\.com|accounts\.google\.com|graph\.facebook\.com|www\.amazon\.com):([A-Za-z0-9_.-]+)(?:\/([^}'",]+))?(?:, *'([^']*)')?)$/
const MAX_VARIABLE = 512

// Known variables stay readable; any other ${prefix:name} is author text and is replaced.
const AWS_VARIABLES = new Set([
  'username', 'userid', 'principaltype', 'sourceip', 'currenttime', 'epochtime', 'securetransport',
  'principalaccount', 'principalorgid', 'principalarn', 'sourceaccount', 'sourcearn', 'sourceorgid',
  'sourcevpce', 'sourcevpc', 'vpcsourceip', 'requestedregion', 'principalservicename', 'federatedprovider',
  'tokenissuetime', 'multifactorauthpresent', 'multifactorauthage', 'referer', 'useragent',
  'sourceidentity', 'calledviafirst', 'calledvialast', 'principalisawsservice', 'viaawsservice',
])
const AWS_TAG_VARIABLES = new Set(['principaltag', 'requesttag', 'resourcetag'])
const STS_VARIABLES = new Set(['rolesessionname', 'sourceidentity'])
const MAX_VARIABLE_NAME = 64

// Keeping "aws" out of text() stops it rewriting every "arn:aws:".
function knownPrefix(prefix: string): boolean {
  const p = prefix.toLowerCase()
  return p === 'aws' || p === 'sts' || p === 'saml' || PUBLIC_IDPS.test(p)
}

function knownVariable(prefix: string, name: string, path: string | undefined): boolean {
  const p = prefix.toLowerCase()
  const n = name.toLowerCase()
  if (n.length > MAX_VARIABLE_NAME) return false
  if (p === 'aws') return path === undefined ? AWS_VARIABLES.has(n) : AWS_TAG_VARIABLES.has(n)
  if (path !== undefined) return false
  if (p === 'sts') return STS_VARIABLES.has(n)
  return p === 'saml' || PUBLIC_IDPS.test(p)
}

// Remembers the next "}", so many "${" without a "}" stay linear.
class VarScanner {
  private close = -2
  constructor(private s: string) {}

  end(i: number): number {
    const s = this.s
    if (s[i] !== '$' || s[i + 1] !== '{' || this.close === -1) return -1
    if (this.close < i + 2) this.close = s.indexOf('}', i + 2)
    const end = this.close
    if (end === -1 || end - i - 2 > MAX_VARIABLE) return -1
    return VARIABLE.test(s.slice(i + 2, end)) ? end : -1
  }
}

function splitOutsideVars(s: string, seps: string): string[] {
  const out: string[] = []
  const vars = new VarScanner(s)
  let start = 0
  for (let i = 0; i < s.length; i++) {
    const end = vars.end(i)
    if (end !== -1) { i = end; continue }
    if (seps.includes(s[i])) {
      out.push(s.slice(start, i), s[i])
      start = i + 1
    }
  }
  out.push(s.slice(start))
  return out
}

// Longer values are replaced one by one; a huge alternation can exceed the regex size limit.
const MAX_PATTERN_VALUE = 4096
const ACCOUNT_ID = /^\d{12}$/
const isWordChar = (c: string | undefined) => c !== undefined && /[\w-]/.test(c)

function replaceWhole(t: string, raw: string, token: string): string {
  let out = ''
  let from = 0
  for (let i = t.indexOf(raw); i !== -1; i = t.indexOf(raw, i + 1)) {
    if (i < from || isWordChar(t[i - 1]) || isWordChar(t[i + raw.length])) continue
    out += t.slice(from, i) + token
    from = i + raw.length
  }
  return out + t.slice(from)
}

export class Redactor {
  private maps = new Map<string, Map<string, string>>()
  // One placeholder per raw value, so it reads the same everywhere it appears.
  private byValue = new Map<string, string>()
  private patternValues = 0

  private token(kind: string, value: string) {
    const existing = this.byValue.get(value)
    if (existing) return existing
    let m = this.maps.get(kind)
    if (!m) { m = new Map(); this.maps.set(kind, m) }
    let t = m.get(value)
    if (!t) {
      t = `${kind}-${m.size + 1}`
      m.set(value, t)
      if (!ACCOUNT_ID.test(value)) this.patternValues++
    }
    this.byValue.set(value, t)
    return t
  }

  private segment(kind: string, seg: string): string {
    if (!seg || seg === 'root') return seg
    const vars = new VarScanner(seg)
    let out = ''
    let start = 0
    const flush = (i: number) => {
      const text = seg.slice(start, i)
      out += /[A-Za-z0-9]/.test(text) ? this.token(kind, text) : text
    }
    for (let i = 0; i < seg.length;) {
      const end = seg[i] === '*' || seg[i] === '?' ? i : vars.end(i)
      if (end === -1) { i++; continue }
      flush(i)
      out += end === i ? seg[i] : this.variable(seg.slice(i, end + 1))
      i = end + 1
      start = i
    }
    flush(seg.length)
    return out
  }

  private variable(v: string): string {
    const m = VARIABLE.exec(v.slice(2, -1))
    if (!m || !m[1]) return v
    const [, prefix, name, path, def] = m
    const known = knownVariable(prefix, name, path)
    const head = known ? `${prefix}:${name}`
      : `${knownPrefix(prefix) ? prefix : this.segment('KEY', prefix)}:${this.segment('KEY', name)}`
    const key = `${head}${path !== undefined ? `/${this.segment('KEY', path)}` : ''}`
    return def === undefined ? `\${${key}}` : `\${${key}, '${def ? this.conditionValue(def) : ''}'}`
  }

  account(id: string) { return this.token('ACCOUNT', id) }

  arn(arn: string): string {
    const f = splitOutsideVars(arn, ':')
    // A malformed ARN can't be split into its parts, so all of it is replaced.
    if (f[0] !== 'arn' || f.length < 11) return this.token('NAME', arn)
    const [partition, service, region, account] = [f[2], f[4], f[6], f[8]]
    const resource = f.slice(10).join('')
    // "aws" is the account of AWS managed policies (arn:aws:iam::aws:policy/...).
    const acct = /^\d{12}$/.test(account) ? this.account(account) : account === 'aws' ? account : this.segment('NAME', account)
    const sep = (p: string) => p === '/' || p === ':'
    let res: string
    if (service === 's3' && !account) {
      const parts = splitOutsideVars(resource, '/')
      res = parts.map((p, i) => sep(p) ? p : this.segment(i === 0 ? 'BUCKET' : 'PATH', p)).join('')
    } else {
      const parts = splitOutsideVars(resource, '/:')
      res = parts.map((p, i) => (i === 0 && parts.length > 1) || sep(p) ? p : this.segment('NAME', p)).join('')
    }
    return `arn:${partition}:${service}:${region}:${acct}:${res}`.replace(/(?<!\d)\d{12}(?!\d)/g, id => this.account(id))
  }

  value(v: string): string {
    if (v.startsWith('arn:')) return this.arn(v)
    if (/^\d{12}$/.test(v)) return this.account(v)
    if (v === '*') return v
    // A plain name or provider URL may identify something, so it is replaced.
    return this.token('NAME', v)
  }

  principal(p: string): string {
    const i = p.indexOf(':')
    if (i > 0 && !p.startsWith('arn:')) {
      const type = p.slice(0, i)
      const value = p.slice(i + 1)
      if (type === 'Service' || value === '*') return p
      if (type === 'Federated' && !value.startsWith('arn:') && PUBLIC_IDPS.test(value)) return p
      // Canonical user IDs identify an AWS account.
      if (type === 'CanonicalUser') return `${type}:${this.token('CANONICAL', value)}`
      return `${type}:${this.value(value)}`
    }
    return this.value(p)
  }

  conditionValue(v: string): string {
    // Longer numbers can be identifiers, such as an employee ID tag value.
    if (v === '*' || /^(true|false)$/i.test(v) || /^-?\d{1,5}(\.\d+)?$/.test(v)) return v
    // A longer host, such as a VPC endpoint DNS name, contains a resource name.
    if (/^[a-z0-9-]+\.amazonaws\.com$/.test(v) || AWS_REGION.test(v)) return v
    if (v.startsWith('arn:') || /^\d{12}$/.test(v)) return this.value(v)
    return this.token('VALUE', v)
  }

  sid(s: string) { return this.token('SID', s) }

  element(k: string) { return this.token('ELEMENT', k) }

  conditionKey(k: string): string {
    const i = k.indexOf(':')
    if (i <= 0) return k
    let prefix = k.slice(0, i)
    let rest = k.slice(i + 1)
    if (/[./]/.test(prefix) && !PUBLIC_IDPS.test(prefix)) prefix = this.value(prefix)
    const j = rest.indexOf('/')
    if (j >= 0) rest = rest.slice(0, j + 1) + this.segment('KEY', rest.slice(j + 1))
    return `${prefix}:${rest}`
  }

  // Bare account IDs are left out of the pattern; the last step replaces every 12-digit ID.
  private textPattern: { size: number; re: RegExp | null; lookup: Map<string, string>; long: (readonly [string, string])[] } | null = null

  text(t: string): string {
    const size = this.patternValues
    if (!this.textPattern || this.textPattern.size !== size) {
      const lookup = new Map<string, string>()
      for (const m of this.maps.values()) for (const [raw, token] of m) if (!ACCOUNT_ID.test(raw)) lookup.set(raw, token)
      // Longest first, so "example-bucket-one" wins over "example-bucket".
      const sorted = [...lookup.keys()].sort((a, b) => b.length - a.length)
      const long = sorted.filter(raw => raw.length > MAX_PATTERN_VALUE).map(raw => [raw, lookup.get(raw) as string] as const)
      const alts = sorted.filter(raw => raw.length <= MAX_PATTERN_VALUE)
        .map(raw => raw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
      // Whole values only, so "prod" doesn't change "production".
      const re = alts.length ? new RegExp(`(?<![\\w-])(?:${alts.join('|')})(?![\\w-])`, 'g') : null
      this.textPattern = { size, re, lookup, long }
    }
    const { re, lookup, long } = this.textPattern
    let out = t
    for (const [raw, token] of long) out = replaceWhole(out, raw, token)
    if (re) out = out.replace(re, m => lookup.get(m) ?? m)
    return out.replace(/\b\d{12}\b/g, id => this.account(id))
  }
}

// Display only: raw is left as is, so never use the result for the Optimize download.
export function redactPolicy(parsed: ParsedPolicy, r = new Redactor()): ParsedPolicy {
  const statements: ParsedStatement[] = parsed.statements.map(st => ({
    ...st,
    sid: st.sid ? r.sid(st.sid) : st.sid,
    actions: st.actions,
    resources: st.resources.map(v => r.value(v)),
    principals: st.principals.map(p => r.principal(p)),
    conditions: st.conditions.map(c => ({ ...c, key: r.conditionKey(c.key), values: c.values.map(v => r.conditionValue(v)) })),
  }))
  // Misspelled or misplaced element names say nothing about the account, so they stay readable.
  const unknownElements = parsed.unknownElements.map(u => (u.suggestion || ELEMENT_NAMES.has(u.key) ? u : { ...u, key: r.element(u.key) }))
  return { ...parsed, statements, unknownElements }
}
