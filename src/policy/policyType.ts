// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { ParsedPolicy } from './types'

// An SCP's Allow "*" is the normal default; in an identity policy it grants full access.
export type PolicyType = 'identity' | 'resource' | 'trust' | 'scp' | 'boundary'

export const POLICY_TYPES: { value: PolicyType; label: string }[] = [
  { value: 'identity', label: 'Identity-based policy' },
  { value: 'resource', label: 'Resource-based policy' },
  { value: 'trust', label: 'Role trust policy' },
  { value: 'scp', label: 'SCP or RCP (Organizations)' },
  { value: 'boundary', label: 'Permissions boundary' },
]

export function isGuardrail(t: PolicyType) {
  return t === 'scp' || t === 'boundary'
}

export function guardrailNotice(t: PolicyType, detected: boolean): string | null {
  if (!isGuardrail(t)) return null
  const name = t === 'scp' ? 'an SCP or RCP' : 'a permissions boundary'
  const why = detected && t === 'scp'
    ? `This policy was detected as ${name} from the input wrapper (Policy.Content, as in organizations describe-policy output).`
    : `The policy type is set to ${name}.`
  return `${why} Grant checks are off for this type: wildcard and sensitive actions, iam:PassRole on any role, NotAction and NotResource with Allow, and all resources. If this is not really ${name}, switch the policy type to see them.`
}

const ASSUME_ACTIONS = /^sts:(assumerole|assumerolewithsaml|assumerolewithwebidentity|tagsession|setsourceidentity|setcontext)$/i

// SCPs look like identity policies, so they are detected only from exact wrapper keys, never a
// substring of a name. Boundaries are never detected: AWS output names them only by ARN.
export function detectPolicyType(parsed: ParsedPolicy): PolicyType {
  const keys = parsed.sourceKeys ?? []
  if (keys[keys.length - 1] === 'AssumeRolePolicyDocument') return 'trust'
  if (keys.length === 2 && keys[0] === 'Policy' && keys[1] === 'Content') return 'scp'

  const withPrincipal = parsed.statements.filter(s => s.raw.Principal !== undefined || s.raw.NotPrincipal !== undefined)
  if (!withPrincipal.length) return 'identity'
  const assumeOnly = withPrincipal.every(s => !s.notAction && s.actions.length > 0 && s.actions.every(a => ASSUME_ACTIONS.test(a)))
  return assumeOnly ? 'trust' : 'resource'
}

// Size limits, in characters of compact JSON, where one applies.
export function sizeLimit(t: PolicyType): { limit: number; label: string } | null {
  switch (t) {
    case 'identity': return { limit: 6144, label: 'customer managed policy limit' }
    case 'boundary': return { limit: 6144, label: 'managed policy limit' }
    case 'scp': return { limit: 5120, label: 'SCP and RCP limit' }
    case 'trust': return { limit: 2048, label: 'default role trust policy limit' }
    default: return null
  }
}
