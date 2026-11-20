// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { z } from 'zod'
import type { ConditionValue, PolicyDocument, ParsedPolicy, ParsedStatement } from './types'

const StrOrArr = z.union([z.string(), z.array(z.string())]).optional()
// IAM accepts strings, numbers, and booleans as condition values, e.g.
// "Bool": { "aws:SecureTransport": false }.
const ConditionScalar = z.union([z.string(), z.number(), z.boolean()])
const ConditionSchema = z
  .record(z.string(), z.record(z.string(), z.union([ConditionScalar, z.array(ConditionScalar)])))
  .optional()
const PrincipalSchema = z
  .union([
    z.string(),
    z.array(z.string()),
    z.record(z.string(), z.union([z.string(), z.array(z.string())])),
  ])
  .optional()

// Loose objects keep elements the schema doesn't know, so a typo such as
// "Actions" can be reported instead of silently dropped.
const StatementSchema = z.looseObject({
  Sid: z.string().optional(),
  Effect: z.union([z.literal('Allow'), z.literal('Deny')]),
  Action: StrOrArr,
  NotAction: StrOrArr,
  Resource: StrOrArr,
  NotResource: StrOrArr,
  Condition: ConditionSchema,
  Principal: PrincipalSchema,
  NotPrincipal: PrincipalSchema
})

const PolicySchema = z.looseObject({
  Version: z.string().optional(),
  Id: z.string().optional(),
  Statement: z.union([StatementSchema, z.array(StatementSchema)])
})

// The elements IAM's policy grammar defines.
export const POLICY_ELEMENTS = ['Version', 'Id', 'Statement']
export const STATEMENT_ELEMENTS = ['Sid', 'Effect', 'Principal', 'NotPrincipal', 'Action', 'NotAction', 'Resource', 'NotResource', 'Condition']

// The element a misspelled key most likely meant: same name ignoring case,
// or the same name with a trailing "s" (Actions, Resources).
function suggestElement(key: string, known: string[]): string | undefined {
  const k = key.toLowerCase()
  return known.find(e => e.toLowerCase() === k || `${e.toLowerCase()}s` === k)
}

function unknownElements(obj: Record<string, unknown>, known: string[], statement?: number) {
  return Object.keys(obj)
    .filter(k => !known.includes(k))
    .map(key => ({ statement, key, suggestion: suggestElement(key, known) }))
}

function toArray(v?: string | string[]): string[] {
  if (!v) return []
  return Array.isArray(v) ? v : [v]
}

function parseConditions(c?: Record<string, Record<string, ConditionValue | ConditionValue[]>>) {
  const out: { operator: string; key: string; values: string[] }[] = []
  if (!c) return out
  for (const [op, kv] of Object.entries(c)) {
    for (const [key, val] of Object.entries(kv)) {
      const vals = Array.isArray(val) ? val : [val]
      out.push({ operator: op, key, values: vals.map(String) })
    }
  }
  return out
}

type PrincipalValue = string | string[] | Record<string, string | string[]>

function parsePrincipal(p?: PrincipalValue): string[] {
  if (!p) return []
  if (typeof p === 'string') return [p]
  if (Array.isArray(p)) return p
  const out: string[] = []
  for (const [k, v] of Object.entries(p)) {
    const vals = Array.isArray(v) ? v : [v]
    for (const val of vals) out.push(`${k}:${val}`)
  }
  return out
}

// Valid JSON with no policy document anywhere in it.
export class NoPolicyFoundError extends Error {
  constructor() {
    super('No policy document found. Expected an object with a "Statement" element, or AWS CLI or CloudFormation output that contains one.')
    this.name = 'NoPolicyFoundError'
  }
}

// Input or policy over the size limits in input.ts.
export class InputTooLargeError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'InputTooLargeError'
  }
}

// A "__proto__" key where the schema would drop it without a trace.
export class UnreadableKeyError extends Error {
  constructor(statement: number, element: string) {
    super(`Statement ${statement} has a "__proto__" key in ${element}. This tool can't read that key, so it does not analyze the policy.`)
    this.name = 'UnreadableKeyError'
  }
}

const hasOwn = (o: unknown, k: string) => !!o && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k)

// JSON.parse keeps a "__proto__" key as an ordinary property, but schema
// validation drops it. As a policy or statement element it is reported as
// an unknown element (IAM rejects the policy). Inside Condition, Principal,
// or NotPrincipal, dropping it would change what the statement means (a
// Deny could lose a condition and look unconditional), so the policy is
// rejected instead.
function rejectNestedProto(input: unknown) {
  if (!input || typeof input !== 'object') return
  const st = (input as Record<string, unknown>).Statement
  const stmts = Array.isArray(st) ? st : [st]
  stmts.forEach((s, i) => {
    if (!s || typeof s !== 'object') return
    const r = s as Record<string, unknown>
    for (const el of ['Principal', 'NotPrincipal', 'Condition']) {
      const v = r[el]
      const nested = el === 'Condition' && v && typeof v === 'object' && Object.values(v).some(o => hasOwn(o, '__proto__'))
      if (hasOwn(v, '__proto__') || nested) throw new UnreadableKeyError(i + 1, el)
    }
  })
}

// One readable line for a failed parse: bad JSON, or JSON that is not a
// valid policy (reported with the path of the first problem).
export function describeParseError(e: unknown): string {
  if (e instanceof SyntaxError) return `Invalid JSON: ${e.message}`
  if (e instanceof NoPolicyFoundError || e instanceof InputTooLargeError || e instanceof UnreadableKeyError) return e.message
  if (e instanceof z.ZodError) {
    const [first, ...rest] = e.issues
    if (!first) return 'Not a valid IAM policy.'
    const path = first.path
      .map((p, i) => (typeof p === 'number' ? `[${p}]` : `${i ? '.' : ''}${String(p)}`))
      .join('')
    const more = rest.length ? ` (${rest.length} more issue${rest.length > 1 ? 's' : ''})` : ''
    return `Not a valid IAM policy: ${path ? `${path}: ` : ''}${first.message}${more}`
  }
  return 'Failed to parse the policy.'
}

export function parsePolicy(input: unknown): ParsedPolicy {
  const data = PolicySchema.parse(input) as PolicyDocument
  rejectNestedProto(input)
  const stmts = Array.isArray(data.Statement) ? data.Statement : [data.Statement]
  // Keys are listed from the input, not the validated copy, which has lost
  // any "__proto__" key.
  const source = input as Record<string, unknown>
  const sourceStmts = (Array.isArray(source.Statement) ? source.Statement : [source.Statement]) as Record<string, unknown>[]

  const parsed: ParsedStatement[] = stmts.map((s, idx) => {
    const actions = toArray(s.Action ?? s.NotAction)
    const resources = toArray(s.Resource ?? s.NotResource)
    const conditions = parseConditions(s.Condition)
    const principals = parsePrincipal(s.Principal ?? s.NotPrincipal)
    return {
      id: `S${idx+1}`,
      sid: s.Sid,
      effect: s.Effect,
      actions,
      resources,
      conditions,
      principals,
      notAction: s.Action === undefined && s.NotAction !== undefined,
      notResource: s.Resource === undefined && s.NotResource !== undefined,
      notPrincipal: s.Principal === undefined && s.NotPrincipal !== undefined,
      raw: s
    }
  })

  const unknown = [
    ...unknownElements(source, POLICY_ELEMENTS),
    ...sourceStmts.flatMap((s, i) => unknownElements(s, STATEMENT_ELEMENTS, i + 1)),
  ]

  return {
    id: 'Policy',
    version: data.Version,
    policyId: data.Id,
    unknownElements: unknown,
    statements: parsed,
    // Compact JSON: no white space between tokens, but spaces inside string
    // values are kept, so the count never comes out below IAM's.
    charCount: JSON.stringify(input).length
  }
}
