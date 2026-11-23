// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Finds the policy inside AWS CLI or CloudFormation output, where it may be a JSON string or
// URL-encoded.

import { InputTooLargeError, NoPolicyFoundError, parsePolicy } from './parse'
import type { ParsedPolicy } from './types'

export interface FoundPolicy {
  policy: unknown
  // e.g. "Policy (JSON string)"; empty for a bare policy.
  path: string
  keys: (string | number)[]
  // Policy documents in the input; only the first is used.
  count: number
}

const MAX_DEPTH = 8
const MAX_NODES = 5000

// Pasted text can be a 1 MB CloudFormation template; the policy must stay under 100,000
// characters, well above IAM's limits.
export const MAX_INPUT_CHARS = 1_000_000
export const MAX_POLICY_CHARS = 100_000

// Decode only a document encoded as a whole, so "%3A" in a value is kept. AWS encodes per
// RFC 3986, so "+" is a literal plus.
function decodeUrl(text: string): string {
  const t = text.trim()
  if (!/^%7B/i.test(t)) return text
  try { return decodeURIComponent(t) } catch { return text }
}

export function parseInputText(text: string): unknown {
  return JSON.parse(decodeUrl(text.trim()))
}

function isPolicy(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v) && 'Statement' in v
}

function parseEmbedded(v: string): unknown {
  const s = decodeUrl(v.trim())
  if (!s.startsWith('{')) return undefined
  try { return JSON.parse(s) } catch { return undefined }
}

export function findPolicy(input: unknown): FoundPolicy | null {
  if (isPolicy(input)) return { policy: input, path: '', keys: [], count: 1 }
  const found: { policy: unknown; path: string; keys: (string | number)[] }[] = []
  let visited = 0

  const walk = (v: unknown, path: string[], keys: (string | number)[], depth: number) => {
    if (depth > MAX_DEPTH || ++visited > MAX_NODES) return
    if (typeof v === 'string') {
      const inner = parseEmbedded(v)
      if (inner !== undefined) walk(inner, [...path.slice(0, -1), `${path[path.length - 1] ?? 'value'} (JSON string)`], keys, depth + 1)
      return
    }
    if (!v || typeof v !== 'object') return
    if (isPolicy(v)) {
      found.push({ policy: v, path: path.join('.'), keys })
      return
    }
    if (Array.isArray(v)) {
      v.forEach((item, i) => walk(item, [...path.slice(0, -1), `${path[path.length - 1] ?? ''}[${i}]`], [...keys, i], depth + 1))
      return
    }
    for (const [k, child] of Object.entries(v)) walk(child, [...path, k], [...keys, k], depth + 1)
  }

  walk(input, [], [], 0)
  if (!found.length) return null
  return { ...found[0], count: found.length }
}

export function loadPolicyText(text: string): ParsedPolicy {
  if (text.length > MAX_INPUT_CHARS) {
    throw new InputTooLargeError(`Input is ${text.length.toLocaleString('en-US')} characters; the limit is ${MAX_INPUT_CHARS.toLocaleString('en-US')}.`)
  }
  const found = findPolicy(parseInputText(text))
  if (!found) throw new NoPolicyFoundError()
  const parsed = parsePolicy(found.policy)
  if (parsed.charCount > MAX_POLICY_CHARS) {
    throw new InputTooLargeError(`The policy is ${parsed.charCount.toLocaleString('en-US')} characters; this tool supports up to ${MAX_POLICY_CHARS.toLocaleString('en-US')}. IAM's own policy size limits are far smaller.`)
  }
  return found.path ? { ...parsed, sourcePath: found.path, sourceKeys: found.keys, sourceCount: found.count } : parsed
}
