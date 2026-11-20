// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { ParsedPolicy, ParsedStatement } from './types'
import { POLICY_ELEMENTS, STATEMENT_ELEMENTS } from './parse'

// Replace identifying values with stable placeholders before a policy is
// shown in a screenshot or export: account IDs become ACCOUNT-1, bucket and
// resource names become BUCKET-1 / NAME-1, Sids become SID-1, and condition
// values become VALUE-1. The same input always maps to the same placeholder,
// so the structure stays readable. Actions, service principals, standard
// condition keys, and in ARNs wildcards and known policy variables are kept;
// tag keys inside variables are replaced.

// AWS Region names: a known geographic prefix, an optional GovCloud or ISO
// partition marker, then direction and number (us-east-1, us-gov-west-1,
// us-isob-east-1). Anything else that merely looks similar, such as
// my-secret-1, is redacted.
const AWS_REGION = /^(us|eu|ap|ca|sa|af|me|il|mx|cn)(-(gov|iso[a-z]?))?-[a-z]+-\d$/

// Federated principals that name a public identity provider rather than a
// customer's own: Cognito, and the web identity providers IAM supports.
const PUBLIC_IDPS = /^(cognito-identity\.amazonaws\.com|accounts\.google\.com|graph\.facebook\.com|www\.amazon\.com)$/

const ELEMENT_NAMES = new Set([...POLICY_ELEMENTS, ...STATEMENT_ELEMENTS])

// The inside of ${...} when it is a policy variable: a key such as
// aws:username or aws:PrincipalTag/<tag-key>, with an optional default
// value (${aws:PrincipalTag/team, 'none'}), or one of the escapes ${*},
// ${?}, ${$}. The prefix before ":" is a service name or a public identity
// provider host. The character classes don't overlap, so the match is
// linear, and VarScanner only tests short strings.
const VARIABLE = /^(?:[*?$]|([A-Za-z0-9-]+|cognito-identity\.amazonaws\.com|accounts\.google\.com|graph\.facebook\.com|www\.amazon\.com):([A-Za-z0-9_.-]+)(?:\/([^}'",]+))?(?:, *'([^']*)')?)$/
const MAX_VARIABLE = 512

// Policy variables shown as written while redacting. Anything else shaped
// like ${prefix:name} could be any text the author chose, so its parts are
// replaced. Names are compared in lowercase, as IAM treats condition key
// names case-insensitively.
const AWS_VARIABLES = new Set([
  'username', 'userid', 'principaltype', 'sourceip', 'currenttime', 'epochtime', 'securetransport',
  'principalaccount', 'principalorgid', 'principalarn', 'sourceaccount', 'sourcearn', 'sourceorgid',
  'sourcevpce', 'sourcevpc', 'vpcsourceip', 'requestedregion', 'principalservicename', 'federatedprovider',
  'tokenissuetime', 'multifactorauthpresent', 'multifactorauthage', 'referer', 'useragent',
  'sourceidentity', 'calledviafirst', 'calledvialast', 'principalisawsservice', 'viaawsservice',
])
// These take a tag key after "/": ${aws:PrincipalTag/<key>}.
const AWS_TAG_VARIABLES = new Set(['principaltag', 'requesttag', 'resourcetag'])
const STS_VARIABLES = new Set(['rolesessionname', 'sourceidentity'])
const MAX_VARIABLE_NAME = 64

// Prefixes that say nothing about the account. Keeping them also keeps the
// word "aws" out of text(), which would otherwise rewrite every "arn:aws:".
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
  // SAML attributes and the claims of public identity providers.
  return p === 'saml' || PUBLIC_IDPS.test(p)
}

// Finds policy variables in one string, left to right. It remembers the
// next "}" (or that there is none), so a long run of "${" without a closing
// "}" costs linear time instead of one search per "${".
class VarScanner {
  private close = -2
  constructor(private s: string) {}

  // Index of the "}" that ends a policy variable starting at i, or -1. Any
  // other ${...} text is not a variable and is redacted as plain text.
  end(i: number): number {
    const s = this.s
    if (s[i] !== '$' || s[i + 1] !== '{' || this.close === -1) return -1
    if (this.close < i + 2) this.close = s.indexOf('}', i + 2)
    const end = this.close
    if (end === -1 || end - i - 2 > MAX_VARIABLE) return -1
    return VARIABLE.test(s.slice(i + 2, end)) ? end : -1
  }
}

// Split on any character in `seps` except inside a policy variable, keeping
// each separator as its own entry, like String.split with a capture group.
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

// Combined text() pattern: values longer than this are replaced one by one
// instead, since a very long alternation can exceed the regex size limit.
const MAX_PATTERN_VALUE = 4096
const ACCOUNT_ID = /^\d{12}$/
const isWordChar = (c: string | undefined) => c !== undefined && /[\w-]/.test(c)

// Replace whole occurrences of `raw` (not preceded or followed by a word
// character or "-", as in text()) with `token`.
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
  // Every raw value gets one placeholder, so the same string reads the same
  // in the diagram, tables, and copied text even if it appears as, say, both
  // a resource name and a condition value.
  private byValue = new Map<string, string>()
  // How many registered values text() matches with its combined pattern.
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

  // Redact one name segment. Wildcards and policy variables anywhere in it
  // ("home-${aws:username}", "*-logs") are kept, and the text between them is
  // replaced. Punctuation alone, such as the "-" in "*-*", identifies nothing.
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

  // A policy variable as shown: a known key is kept, but a tag key inside it
  // (${aws:PrincipalTag/<tag-key>}) and a default value are redacted, the
  // same way as in condition keys and values. An unknown key keeps only its
  // shape: ${example-app:example-name} becomes ${KEY-1:KEY-2}, and
  // ${aws:example-name} becomes ${aws:KEY-3}.
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
    // Split on ":" outside ${...}, so ${aws:username} stays one piece.
    const f = splitOutsideVars(arn, ':')
    // A malformed ARN can't be split into its parts, so all of it is replaced.
    if (f[0] !== 'arn' || f.length < 11) return this.token('NAME', arn)
    const [partition, service, region, account] = [f[2], f[4], f[6], f[8]]
    const resource = f.slice(10).join('')
    // "aws" is the account of AWS managed policies (arn:aws:iam::aws:policy/...).
    // Any other non-numeric account field keeps only wildcards and policy
    // variables.
    const acct = /^\d{12}$/.test(account) ? this.account(account) : account === 'aws' ? account : this.segment('NAME', account)
    const sep = (p: string) => p === '/' || p === ':'
    let res: string
    if (service === 's3' && !account) {
      // arn:aws:s3:::bucket/key/path
      const parts = splitOutsideVars(resource, '/')
      res = parts.map((p, i) => sep(p) ? p : this.segment(i === 0 ? 'BUCKET' : 'PATH', p)).join('')
    } else {
      // type/name/... or type:name; the first segment is a resource type.
      const parts = splitOutsideVars(resource, '/:')
      res = parts.map((p, i) => (i === 0 && parts.length > 1) || sep(p) ? p : this.segment('NAME', p)).join('')
    }
    // An account ID outside the account field, such as in a shifted or
    // unusual ARN, is still replaced.
    return `arn:${partition}:${service}:${region}:${acct}:${res}`.replace(/(?<!\d)\d{12}(?!\d)/g, id => this.account(id))
  }

  // A resource, principal value, or other string that may hold identifiers.
  value(v: string): string {
    if (v.startsWith('arn:')) return this.arn(v)
    if (/^\d{12}$/.test(v)) return this.account(v)
    if (v === '*') return v
    // Anything else (a plain name, a provider URL) may identify something,
    // so it gets a placeholder rather than passing through.
    return this.token('NAME', v)
  }

  // Principal as stored in ParsedStatement.principals, e.g. "AWS:arn:...".
  principal(p: string): string {
    const i = p.indexOf(':')
    if (i > 0 && !p.startsWith('arn:')) {
      const type = p.slice(0, i)
      const value = p.slice(i + 1)
      // Service principals (lambda.amazonaws.com) and public identity
      // providers are not identifying.
      if (type === 'Service' || value === '*') return p
      if (type === 'Federated' && !value.startsWith('arn:') && PUBLIC_IDPS.test(value)) return p
      // Canonical user IDs identify an AWS account.
      if (type === 'CanonicalUser') return `${type}:${this.token('CANONICAL', value)}`
      return `${type}:${this.value(value)}`
    }
    return this.value(p)
  }

  conditionValue(v: string): string {
    // Keep booleans and short numbers (TLS versions, ports, ages in seconds).
    // Longer numbers can be identifiers, such as an employee ID tag value.
    if (v === '*' || /^(true|false)$/i.test(v) || /^-?\d{1,5}(\.\d+)?$/.test(v)) return v
    // Keep service names (lambda.amazonaws.com) and Regions (us-east-1). A
    // longer host such as example-bucket.s3.amazonaws.com or a VPC endpoint
    // DNS name contains a resource name, so it is redacted.
    if (/^[a-z0-9-]+\.amazonaws\.com$/.test(v) || AWS_REGION.test(v)) return v
    if (v.startsWith('arn:') || /^\d{12}$/.test(v)) return this.value(v)
    return this.token('VALUE', v)
  }

  sid(s: string) { return this.token('SID', s) }

  // A key that is not a policy element, as named in an UNKNOWN_ELEMENT
  // finding. Registering it lets text() replace it there.
  element(k: string) { return this.token('ELEMENT', k) }

  // Condition keys can carry identifiers in two places: a web identity
  // provider host before the ":" (oidc.eks.<region>.amazonaws.com/id/<id>:sub)
  // and a tag name after "/" (aws:ResourceTag/<TagKey>). Standard keys such
  // as aws:SourceVpce are kept as they are.
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

  // Replace every identifier this redactor has already seen inside free text,
  // e.g. a finding's description. One combined pattern, rebuilt only when new
  // values have been registered, so this stays fast over thousands of rows.
  // Bare account IDs are left out of the pattern: the last step replaces
  // every 12-digit ID with the same placeholder anyway. That step registers
  // IDs it has not seen, which would otherwise force a rebuild on each call
  // that meets a new one.
  private textPattern: { size: number; re: RegExp | null; lookup: Map<string, string>; long: (readonly [string, string])[] } | null = null

  text(t: string): string {
    const size = this.patternValues
    if (!this.textPattern || this.textPattern.size !== size) {
      const lookup = new Map<string, string>()
      for (const m of this.maps.values()) for (const [raw, token] of m) if (!ACCOUNT_ID.test(raw)) lookup.set(raw, token)
      // Longest first, so "example-bucket-one" wins over "example-bucket".
      const sorted = [...lookup.keys()].sort((a, b) => b.length - a.length)
      // Very long values are replaced directly, before the pattern runs.
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

// Redacts the fields the diagram and tables display. `raw` is left as is, so
// use the result for display only, never for the Optimize download.
export function redactPolicy(parsed: ParsedPolicy, r = new Redactor()): ParsedPolicy {
  const statements: ParsedStatement[] = parsed.statements.map(st => ({
    ...st,
    sid: st.sid ? r.sid(st.sid) : st.sid,
    actions: st.actions,
    resources: st.resources.map(v => r.value(v)),
    principals: st.principals.map(p => r.principal(p)),
    conditions: st.conditions.map(c => ({ ...c, key: r.conditionKey(c.key), values: c.values.map(v => r.conditionValue(v)) })),
  }))
  // Unknown keys are free text the policy author chose. A near miss of a real
  // element ("Actions"), or an element in the wrong place ("Version" inside a
  // statement), says nothing about the account, so it stays readable.
  const unknownElements = parsed.unknownElements.map(u => (u.suggestion || ELEMENT_NAMES.has(u.key) ? u : { ...u, key: r.element(u.key) }))
  return { ...parsed, statements, unknownElements }
}
