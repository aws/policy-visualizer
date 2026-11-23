// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { ParsedPolicy, ParsedStatement, Statement } from './types'
import { detectPolicyType, isGuardrail, sizeLimit, type PolicyType } from './policyType'
import { stripVariables, wildcardMatch } from './evaluate'

function coversAnyRole(r: string): boolean {
  if (r === '*') return true
  const partition = /^arn:([a-z-]+):/.exec(r)?.[1] ?? 'aws'
  const named = /^arn:[^:]+:iam::(\d{12}):/.exec(r)?.[1]
  const account = named ?? '111122223333'
  const probes = [`arn:${partition}:iam::${account}:role/zz-probe-role-q7`, `arn:${partition}:iam::${account}:role/zz/probe/path/q7`]
  return probes.every(p => wildcardMatch(r, p))
}

// Excluding one role, or one account's roles, still leaves almost every role to pass. The probe
// ARNs share nothing beyond what every role ARN has, and are tried in every partition.
function excludesEveryRole(r: string, partitions: string[]): boolean {
  if (r === '*') return true
  return partitions.every(partition => ['111122223333', '444455556666'].every(account =>
    ['x', 'Q7/k', '_+=,.@-'].every(name => wildcardMatch(r, `arn:${partition}:iam::${account}:role/${name}`))))
}

// Always includes "aws", which can only add findings.
function policyPartitions(parsed: ParsedPolicy): string[] {
  const out = new Set(['aws'])
  for (const st of parsed.statements) {
    for (const v of [...st.resources, ...st.principals, ...st.conditions.flatMap(c => c.values)]) {
      const m = /arn:([a-z0-9-]+):/.exec(v)
      if (m) out.add(m[1])
    }
  }
  return [...out]
}

const anyRoleIn = (st: ParsedStatement, partitions: string[]) =>
  st.notResource
    ? !partitions.every(p => st.resources.some(r => excludesEveryRole(r, [p])))
    : st.resources.some(coversAnyRole)

// svc:*, svc:**, svc:?* and similar match every action in the service in practice.
const allWild = (v: string) => v.includes('*') && /^[*?]+$/.test(v)
function isServiceWildcard(action: string): boolean {
  const colon = action.indexOf(':')
  return colon > 0 && /^[a-z0-9-]+$/i.test(action.slice(0, colon)) && allWild(action.slice(colon + 1))
}
function isAllActions(action: string): boolean {
  if (allWild(action)) return true
  const colon = action.indexOf(':')
  return colon > 0 && allWild(action.slice(0, colon)) && allWild(action.slice(colon + 1))
}

// An ARN with no account, Region, or resource name (arn:aws:s3:::*) covers the whole service.
function serviceWide(r: string): string | null {
  const m = /^arn:[^:]+:([^:]+):([^:]*):([^:]*):(.+)$/.exec(r)
  if (!m) return null
  const [, service, region, account, resource] = m
  const open = (v: string) => v === '' || v === '*'
  if (!open(region) || !open(account)) return null
  // S3 ARNs have no resource type, so "bucket/*" is one bucket; elsewhere "table/*" is every table.
  const all = service === 's3' ? /^\*(\/\*)?$/ : /^(\*|[A-Za-z-]+[/:]\*)$/
  return all.test(resource) ? service : null
}

// Offline checks; nothing is sent anywhere.

export type Severity = 'high' | 'medium' | 'low' | 'info'

export interface Finding {
  code: string
  severity: Severity
  title: string
  detail: string
  // 1-based statement number, when the finding is about one statement.
  statement?: number
  sid?: string
}

export interface AnalyzeOptions {
  // When set, principals from other accounts are reported as cross-account.
  accountId?: string
  policyType?: PolicyType
}


const SEVERITY_ORDER: Severity[] = ['high', 'medium', 'low', 'info']

// Lowercase: IAM matches action names case-insensitively.
const SENSITIVE_EXACT = new Set(['s3:putbucketpolicy', 's3:deletebucketpolicy', 's3:putbucketacl', 's3:putobjectacl'])

// Mutating IAM and Organizations actions, any KMS action, and some S3 access-control writes.
function isSensitiveName(lower: string) {
  if (SENSITIVE_EXACT.has(lower)) return true
  const [svc, op = ''] = lower.split(':')
  if (!op) return false
  if (svc === 'kms') return true
  if (svc === 'iam' || svc === 'organizations') return !/^(get|list|describe)/.test(op)
  return false
}

// Probe names for matching wildcard patterns such as iam:*Role or s3:PutBucket*.
const SENSITIVE_NAMES: string[] = [
  ...[...SENSITIVE_EXACT],
  ...[
    'AddClientIDToOpenIDConnectProvider', 'AddRoleToInstanceProfile', 'AddUserToGroup', 'AttachGroupPolicy',
    'AttachRolePolicy', 'AttachUserPolicy', 'ChangePassword', 'CreateAccessKey', 'CreateAccountAlias',
    'CreateGroup', 'CreateInstanceProfile', 'CreateLoginProfile', 'CreateOpenIDConnectProvider', 'CreatePolicy',
    'CreatePolicyVersion', 'CreateRole', 'CreateSAMLProvider', 'CreateServiceLinkedRole',
    'CreateServiceSpecificCredential', 'CreateUser', 'CreateVirtualMFADevice', 'DeactivateMFADevice',
    'DeleteAccessKey', 'DeleteAccountAlias', 'DeleteAccountPasswordPolicy', 'DeleteGroup', 'DeleteGroupPolicy',
    'DeleteInstanceProfile', 'DeleteLoginProfile', 'DeleteOpenIDConnectProvider', 'DeletePolicy',
    'DeletePolicyVersion', 'DeleteRole', 'DeleteRolePermissionsBoundary', 'DeleteRolePolicy',
    'DeleteSAMLProvider', 'DeleteServerCertificate', 'DeleteServiceLinkedRole', 'DeleteServiceSpecificCredential',
    'DeleteSigningCertificate', 'DeleteSSHPublicKey', 'DeleteUser', 'DeleteUserPermissionsBoundary',
    'DeleteUserPolicy', 'DeleteVirtualMFADevice', 'DetachGroupPolicy', 'DetachRolePolicy', 'DetachUserPolicy',
    'EnableMFADevice', 'PassRole', 'PutGroupPolicy', 'PutRolePermissionsBoundary', 'PutRolePolicy',
    'PutUserPermissionsBoundary', 'PutUserPolicy', 'RemoveClientIDFromOpenIDConnectProvider',
    'RemoveRoleFromInstanceProfile', 'RemoveUserFromGroup', 'ResetServiceSpecificCredential', 'ResyncMFADevice',
    'SetDefaultPolicyVersion', 'SetSecurityTokenServicePreferences', 'TagRole', 'TagUser', 'UntagRole',
    'UntagUser', 'UpdateAccessKey', 'UpdateAccountPasswordPolicy', 'UpdateAssumeRolePolicy', 'UpdateGroup',
    'UpdateLoginProfile', 'UpdateOpenIDConnectProviderThumbprint', 'UpdateRole', 'UpdateRoleDescription',
    'UpdateSAMLProvider', 'UpdateServerCertificate', 'UpdateServiceSpecificCredential',
    'UpdateSigningCertificate', 'UpdateSSHPublicKey', 'UpdateUser', 'UploadServerCertificate',
    'UploadSigningCertificate', 'UploadSSHPublicKey',
  ].map(op => `iam:${op}`),
  ...[
    'AcceptHandshake', 'AttachPolicy', 'CancelHandshake', 'CloseAccount', 'CreateAccount',
    'CreateGovCloudAccount', 'CreateOrganization', 'CreateOrganizationalUnit', 'CreatePolicy',
    'DeclineHandshake', 'DeleteOrganization', 'DeleteOrganizationalUnit', 'DeletePolicy',
    'DeleteResourcePolicy', 'DeregisterDelegatedAdministrator', 'DetachPolicy', 'DisableAWSServiceAccess',
    'DisablePolicyType', 'EnableAllFeatures', 'EnableAWSServiceAccess', 'EnablePolicyType',
    'InviteAccountToOrganization', 'LeaveOrganization', 'MoveAccount', 'PutResourcePolicy',
    'RegisterDelegatedAdministrator', 'RemoveAccountFromOrganization', 'TagResource', 'UntagResource',
    'UpdateOrganizationalUnit', 'UpdatePolicy',
  ].map(op => `organizations:${op}`),
  ...[
    'CancelKeyDeletion', 'CreateAlias', 'CreateGrant', 'CreateKey', 'Decrypt', 'DeleteAlias',
    'DeleteImportedKeyMaterial', 'DescribeKey', 'DisableKey', 'DisableKeyRotation', 'EnableKey',
    'EnableKeyRotation', 'Encrypt', 'GenerateDataKey', 'GenerateDataKeyPair', 'GenerateDataKeyWithoutPlaintext',
    'GenerateMac', 'GetKeyPolicy', 'GetPublicKey', 'ImportKeyMaterial', 'ListGrants', 'ListKeys',
    'PutKeyPolicy', 'ReEncryptFrom', 'ReEncryptTo', 'ReplicateKey', 'RetireGrant', 'RevokeGrant',
    'ScheduleKeyDeletion', 'Sign', 'TagResource', 'UntagResource', 'UpdateAlias', 'UpdateKeyDescription',
    'Verify',
  ].map(op => `kms:${op}`),
].map(a => a.toLowerCase())

// kms is always sensitive; iam and organizations unless the literal prefix is get, list, or
// describe. iam:G* counts because it also covers Generate*.
function sensitiveByRule(lower: string): boolean {
  const colon = lower.indexOf(':')
  if (colon <= 0) return false
  const svc = lower.slice(0, colon)
  const op = lower.slice(colon + 1)
  if (!op || svc.includes('*') || svc.includes('?')) return false
  if (svc === 'kms') return true
  if (svc !== 'iam' && svc !== 'organizations') return false
  const wild = op.search(/[*?]/)
  const literal = wild === -1 ? op : op.slice(0, wild)
  return !/^(get|list|describe)/.test(literal)
}

function sensitiveCoverage(action: string): { sensitive: boolean; onlyPassRole: boolean } {
  const lower = action.toLowerCase()
  if (!/[*?]/.test(lower)) return { sensitive: isSensitiveName(lower), onlyPassRole: lower === 'iam:passrole' }
  const listed = SENSITIVE_NAMES.filter(name => wildcardMatch(lower, name))
  // No other IAM action starts with "Pass", so iam:Pass* can only mean PassRole.
  const onlyPassRole = listed.length > 0 && listed.every(n => n === 'iam:passrole') && lower.startsWith('iam:pass')
  return { sensitive: listed.length > 0 || sensitiveByRule(lower), onlyPassRole }
}

const coversPassRole = (action: string) => wildcardMatch(action, 'iam:PassRole', true)

// Keys that limit who can call. aws:SecureTransport or aws:CurrentTime don't.
const CALLER_KEYS = new Set([
  'aws:principalorgid', 'aws:principalorgpaths', 'aws:principalaccount', 'aws:principalarn',
  'aws:sourceaccount', 'aws:sourcearn', 'aws:sourceorgid', 'aws:sourceorgpaths',
  'aws:sourcevpce', 'aws:sourcevpc', 'aws:sourceip',
])

// Not* operators match everything except the values, IfExists and ForAllValues pass on a missing
// key, and Null only checks presence, so none of these limit the caller.
const LIMITING_OPERATOR = /^(ForAnyValue:)?(StringEquals|StringEqualsIgnoreCase|StringLike|ArnEquals|ArnLike|IpAddress)$/i

const hasWildcard = (v: string) => v.includes('*') || v.includes('?')

// A wildcard value limits the caller only if the literal part pins it down: an ARN needs a literal
// partition, service, and 12-digit account; other values allow wildcards only after the last "/".
function likeValueLimits(v: string): boolean {
  if (!hasWildcard(v)) return true
  const f = v.split(':')
  if (f[0] === 'arn') {
    if (f.length < 6) return false
    const [, partition, service, , account] = f
    return !hasWildcard(partition) && !hasWildcard(service) && /^\d{12}$/.test(account)
  }
  const slash = v.lastIndexOf('/')
  return slash > 0 && !hasWildcard(v.slice(0, slash))
}

function ipv4Octets(v: string): number[] | null {
  const parts = v.split('.')
  if (parts.length !== 4 || !parts.every(p => /^\d{1,3}$/.test(p) && Number(p) <= 255)) return null
  return parts.map(Number)
}

// Handles a trailing dotted quad (::ffff:192.0.2.1) and "::" for one or more zero groups.
function ipv6Groups(v: string): number[] | null {
  let text = v.toLowerCase()
  const last = text.lastIndexOf(':')
  if (text.slice(last + 1).includes('.')) {
    const q = ipv4Octets(text.slice(last + 1))
    if (!q) return null
    text = `${text.slice(0, last + 1)}${((q[0] << 8) | q[1]).toString(16)}:${((q[2] << 8) | q[3]).toString(16)}`
  }
  const halves = text.split('::')
  if (halves.length > 2) return null
  const groups = (h: string) => (h === '' ? [] : h.split(':'))
  const left = groups(halves[0])
  const right = halves.length === 2 ? groups(halves[1]) : []
  if (![...left, ...right].every(g => /^[0-9a-f]{1,4}$/.test(g))) return null
  const missing = 8 - left.length - right.length
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null
  return [...left, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...right].map(g => parseInt(g, 16))
}

// Limits the caller only at /8 or longer for IPv4 and /16 for IPv6, or /104 inside ::/80, which
// holds IPv4-mapped addresses. Anything that does not parse keeps the finding High.
function ipValueLimits(v: string): boolean {
  const slash = v.indexOf('/')
  const addr = slash === -1 ? v : v.slice(0, slash)
  const bits = slash === -1 ? undefined : v.slice(slash + 1)
  if (bits !== undefined && !/^\d{1,3}$/.test(bits)) return false
  if (ipv4Octets(addr)) {
    const prefix = bits === undefined ? 32 : Number(bits)
    return prefix <= 32 && prefix >= 8
  }
  const g = addr.includes(':') ? ipv6Groups(addr) : null
  if (!g) return false
  const prefix = bits === undefined ? 128 : Number(bits)
  if (prefix > 128) return false
  const embedsIpv4 = g.slice(0, 5).every(x => x === 0)
  return prefix >= (embedsIpv4 ? 104 : 16)
}

function valueLimits(operator: string, v: string): boolean {
  // A policy variable compares the caller with itself, which every caller passes.
  if (!v || v.includes('${') || /^[*?]+$/.test(v)) return false
  if (/IpAddress$/i.test(operator)) return ipValueLimits(v)
  // ArnEquals takes wildcards in each ARN part, the same as ArnLike.
  if (/(Like|ArnEquals)$/i.test(operator)) return likeValueLimits(v)
  return true
}

function callerLimits(st: ParsedStatement): string[] {
  const keys = st.conditions
    .filter(c => CALLER_KEYS.has(c.key.toLowerCase()) && LIMITING_OPERATOR.test(c.operator) &&
      c.values.length > 0 && c.values.every(v => valueLimits(c.operator, v.trim())))
    .map(c => c.key)
  return [...new Set(keys)]
}

// Common S3 object and bucket actions only; unlisted actions aren't checked.
const S3_OBJECT_ACTIONS = new Set([
  'getobject', 'putobject', 'deleteobject', 'getobjectversion', 'deleteobjectversion',
  'getobjectacl', 'putobjectacl', 'getobjecttagging', 'putobjecttagging',
  'deleteobjecttagging', 'restoreobject', 'abortmultipartupload', 'listmultipartuploadparts',
])
const S3_BUCKET_ACTIONS = new Set([
  'listbucket', 'listbucketversions', 'listbucketmultipartuploads', 'getbucketlocation',
  'getbucketpolicy', 'putbucketpolicy', 'deletebucketpolicy', 'getbucketacl', 'putbucketacl',
  'getbucketversioning', 'putbucketversioning',
])

type PrincipalEntry = { type: string; value: string }

function principalEntries(p: Statement['Principal']): PrincipalEntry[] {
  if (!p) return []
  if (typeof p === 'string') return [{ type: p === '*' ? '*' : '', value: p }]
  if (Array.isArray(p)) return p.map(value => ({ type: '', value }))
  const out: PrincipalEntry[] = []
  for (const [type, v] of Object.entries(p)) {
    for (const value of Array.isArray(v) ? v : [v]) out.push({ type, value })
  }
  return out
}

function isPublic(e: PrincipalEntry) {
  return e.value === '*' && (e.type === '*' || e.type === 'AWS' || e.type === '')
}

export function principalAccount(e: PrincipalEntry): string | null {
  if (e.type !== 'AWS' && e.type !== '') return null
  if (/^\d{12}$/.test(e.value)) return e.value
  const m = /^arn:aws[a-z-]*:(?:iam|sts)::(\d{12}):/.exec(e.value)
  return m ? m[1] : null
}

function list(values: string[], max = 4) {
  const shown = values.slice(0, max).join(', ')
  return values.length > max ? `${shown} and ${values.length - max} more` : shown
}

function s3Resource(arn: string): 'bucket' | 'object' | null {
  const m = /^arn:aws[a-z-]*:s3:::(.+)$/.exec(arn)
  if (!m) return null
  return m[1].includes('/') ? 'object' : 'bucket'
}

function s3ActionKind(action: string): 'bucket' | 'object' | null {
  const [svc, op] = action.split(':')
  if (svc?.toLowerCase() !== 's3' || !op) return null
  const name = op.toLowerCase()
  if (S3_OBJECT_ACTIONS.has(name)) return 'object'
  if (S3_BUCKET_ACTIONS.has(name)) return 'bucket'
  return null
}

function conditionFindings(st: ParsedStatement, n: number): Finding[] {
  const out: Finding[] = []
  const at = { statement: n, sid: st.sid }
  for (const c of st.conditions) {
    const setOp = /^ForAllValues:/i.test(c.operator) ? 'all' : /^ForAnyValue:/i.test(c.operator) ? 'any' : null
    const base = c.operator.replace(/^(ForAllValues|ForAnyValue):/i, '').replace(/IfExists$/, '')
    const nullChecked = st.conditions.some(o =>
      o.operator === 'Null' && o.key.toLowerCase() === c.key.toLowerCase() && o.values.includes('false'))

    if (st.effect === 'Allow' && setOp === 'all' && !nullChecked) {
      out.push({ ...at, code: 'FORALLVALUES_MISSING_KEY', severity: 'medium',
        title: 'ForAllValues passes when the key is missing',
        detail: `${c.operator} on ${c.key} is also true when the request has no ${c.key} or an empty list. Add "Null": {"${c.key}": "false"}, or use ForAnyValue if one match is enough.` })
    }
    if (st.effect === 'Deny' && setOp === 'any') {
      out.push({ ...at, code: 'DENY_FORANYVALUE_MISSING_KEY', severity: 'low',
        title: 'ForAnyValue Deny skips requests without the key',
        detail: `${c.operator} on ${c.key} is false when the request has no ${c.key}, so those requests are not denied. Add a Deny with "Null": {"${c.key}": "true"} if they should be.` })
    }
    // Wildcards are literal in exact-match operators; ${...} variables are not wildcards.
    if (/^String(Not)?Equals(IgnoreCase)?$/i.test(base) &&
        c.values.some(v => /[*?]/.test(stripVariables(v)))) {
      out.push({ ...at, code: 'WILDCARD_IN_EXACT_MATCH', severity: 'medium',
        title: 'Wildcard in an exact-match condition',
        detail: `${c.operator} compares values literally, so "*" and "?" in the ${c.key} values match only those characters. Use StringLike or StringNotLike for wildcard matching.` })
    }
    if (st.effect === 'Allow' && /IfExists$/.test(c.operator)) {
      out.push({ ...at, code: 'IFEXISTS_ALLOW', severity: 'low',
        title: 'IfExists condition on an Allow',
        detail: `${c.operator} on ${c.key} also passes when the request has no ${c.key}, so those requests are allowed.` })
    }
  }
  return out
}

function statementFindings(st: ParsedStatement, n: number, opts: AnalyzeOptions & { policyType: PolicyType; partitions: string[] }): Finding[] {
  const out: Finding[] = conditionFindings(st, n)
  const at = { statement: n, sid: st.sid }
  if (st.effect !== 'Allow') return out
  // SCPs, RCPs, and boundaries only cap permissions, so "grants too much" checks don't apply.
  const guardrail = isGuardrail(opts.policyType)

  const principals = principalEntries(st.raw.Principal)
  if (st.notPrincipal) {
    out.push({ ...at, code: 'ALLOW_NOT_PRINCIPAL', severity: 'high',
      title: 'Allow with NotPrincipal',
      detail: 'Grants access to everyone except the listed principals, including anonymous users.' })
  }
  if (principals.some(isPublic)) {
    const limits = callerLimits(st)
    const others = [...new Set(st.conditions.map(c => c.key))]
    out.push(limits.length
      ? { ...at, code: 'PUBLIC_PRINCIPAL_CONDITIONAL', severity: 'medium',
          title: 'Public principal limited by conditions',
          detail: `Principal "*" allows anyone that meets the conditions on ${list(limits)}. Check that they restrict access as intended.` }
      : { ...at, code: 'PUBLIC_PRINCIPAL', severity: 'high',
          title: 'Public access',
          detail: others.length
            ? `Principal "*" allows anyone, including anonymous users. Its conditions (${list(others)}) do not limit who can call.`
            : 'Principal "*" with no conditions allows anyone, including anonymous users.' })
  }
  if (opts.accountId) {
    const others = [...new Set(principals.map(principalAccount).filter((a): a is string => !!a && a !== opts.accountId))]
    if (others.length) {
      out.push({ ...at, code: 'CROSS_ACCOUNT_PRINCIPAL', severity: 'medium',
        title: 'Cross-account access',
        detail: `Grants access to principals in other AWS accounts: ${list(others)}.` })
    }
  }

  const allActions = st.actions.some(isAllActions)
  if (guardrail) {
    // skip grant checks
  } else if (st.notAction) {
    out.push({ ...at, code: 'ALLOW_NOT_ACTION', severity: 'high',
      title: 'Allow with NotAction',
      detail: `Allows every action except ${list(st.actions)}, including actions added to AWS in the future.` })
  } else {
    const wildServices = st.actions.filter(isServiceWildcard)
    if (allActions) {
      out.push({ ...at, code: 'ALL_ACTIONS', severity: 'high',
        title: 'Allows all actions', detail: `Action ${list(st.actions.filter(isAllActions).map(a => `"${a}"`))} allows every action in every AWS service.` })
    } else if (wildServices.length) {
      out.push({ ...at, code: 'SERVICE_WILDCARD', severity: 'medium',
        title: 'Allows all actions in a service',
        detail: `Allows every action in: ${list(wildServices.map(a => a.split(':')[0]))}.` })
    }
    // PassRole on any role and Action "*" have their own findings.
    const passRoleOnAny = anyRoleIn(st, opts.partitions)
    const sensitive = st.actions.filter(a => {
      if (isAllActions(a)) return false
      const { sensitive, onlyPassRole } = sensitiveCoverage(a)
      return sensitive && !(passRoleOnAny && onlyPassRole)
    })
    if (sensitive.length) {
      out.push({ ...at, code: 'SENSITIVE_ACTIONS', severity: 'medium',
        title: 'Sensitive actions',
        detail: `Includes IAM, Organizations, KMS, or S3 access-control actions that need tight scoping: ${list(sensitive)}.` })
    }
  }

  const anyResource = !st.notResource && st.resources.includes('*')
  if (guardrail) {
    // skip grant checks
  } else if (st.notResource) {
    out.push({ ...at, code: 'ALLOW_NOT_RESOURCE', severity: 'medium',
      title: 'Allow with NotResource',
      detail: `Applies to every resource except ${list(st.resources)}.` })
  } else if (!anyResource && !allActions && st.resources.some(r => serviceWide(r))) {
    const wide = st.resources.filter(r => serviceWide(r))
    out.push({ ...at, code: 'SERVICE_WIDE_RESOURCES', severity: 'low',
      title: 'Applies to every resource of a service',
      detail: `${list(wide)} names no account, Region, or specific resource, so it covers every matching resource. Scope it to specific ARNs where the actions support it.` })
  } else if (anyResource && !allActions) {
    out.push({ ...at, code: 'ALL_RESOURCES', severity: 'low',
      title: 'Applies to all resources',
      detail: 'Resource "*" applies to every resource. Scope it to specific ARNs where the actions support it.' })
  }

  const passRole = !st.notAction && st.actions.some(coversPassRole)
  if (!guardrail && passRole && anyRoleIn(st, opts.partitions)) {
    const scopedToService = st.conditions.some(c => c.key.toLowerCase() === 'iam:passedtoservice')
    const which = st.notResource ? `every role except ${list(st.resources)}` : 'any role'
    out.push({ ...at, code: 'PASSROLE_ANY_ROLE', severity: scopedToService ? 'medium' : 'high',
      title: 'iam:PassRole on any role',
      detail: scopedToService
        ? `Allows passing ${which}, limited to the services in iam:PassedToService. Scope Resource to specific role ARNs.`
        : `Allows passing ${which} to any service, a common privilege escalation path. Scope Resource to specific role ARNs.` })
  }

  if (!st.notAction && !st.notResource) {
    const s3Arns = st.resources.map(s3Resource).filter(Boolean)
    if (s3Arns.length) {
      const objectActions = st.actions.filter(a => s3ActionKind(a) === 'object')
      const bucketActions = st.actions.filter(a => s3ActionKind(a) === 'bucket')
      if (objectActions.length && !s3Arns.includes('object')) {
        out.push({ ...at, code: 'S3_OBJECT_ACTION_ON_BUCKET', severity: 'medium',
          title: 'S3 object actions on a bucket ARN',
          detail: `${list(objectActions)} act on objects, but every S3 resource here is a bucket ARN. Add an object ARN such as arn:aws:s3:::bucket-name/*, or the statement grants nothing for these actions.` })
      }
      if (bucketActions.length && !s3Arns.includes('bucket')) {
        out.push({ ...at, code: 'S3_BUCKET_ACTION_ON_OBJECT', severity: 'medium',
          title: 'S3 bucket actions on an object ARN',
          detail: `${list(bucketActions)} act on buckets, but every S3 resource here is an object ARN. Add the bucket ARN, such as arn:aws:s3:::bucket-name, or the statement grants nothing for these actions.` })
      }
    }
  }

  return out
}

const TYPE_NAMES: Record<PolicyType, string> = {
  identity: 'identity-based policies', resource: 'resource-based policies', trust: 'role trust policies',
  scp: 'SCPs and RCPs', boundary: 'permissions boundaries',
}

function policyFindings(parsed: ParsedPolicy, opts: AnalyzeOptions & { policyType: PolicyType }): Finding[] {
  const out: Finding[] = []
  const type = opts.policyType

  // Every statement needs Action or NotAction; identity policies and boundaries also need Resource or NotResource.
  parsed.statements.forEach((st, i) => {
    const at = { statement: i + 1, sid: st.sid }
    if (st.raw.Action === undefined && st.raw.NotAction === undefined) {
      out.push({ ...at, code: 'MISSING_ACTION', severity: 'medium', title: 'No Action or NotAction',
        detail: 'Every statement needs an Action or NotAction element, so IAM rejects the policy.' })
    }
    if ((type === 'identity' || type === 'boundary') && st.raw.Resource === undefined && st.raw.NotResource === undefined) {
      out.push({ ...at, code: 'MISSING_RESOURCE', severity: 'medium', title: 'No Resource or NotResource',
        detail: `Statements in ${TYPE_NAMES[type]} need a Resource or NotResource element, so IAM rejects the policy.` })
    }
  })

  // IAM rejects keys outside its grammar.
  for (const u of parsed.unknownElements) {
    const where = u.statement ? `Statement ${u.statement} has` : 'The policy has'
    const hint = u.suggestion ? ` Did you mean "${u.suggestion}"?` : ''
    out.push({ code: 'UNKNOWN_ELEMENT', severity: 'medium', statement: u.statement,
      title: 'Unknown policy element',
      detail: `${where} "${u.key}", which is not a policy element, so IAM rejects the policy.${hint}` })
  }

  const withPrincipal = parsed.statements.filter(s => s.raw.Principal !== undefined || s.raw.NotPrincipal !== undefined)
  if ((type === 'identity' || type === 'boundary') && withPrincipal.length) {
    out.push({ code: 'PRINCIPAL_NOT_ALLOWED', severity: 'medium', title: 'Principal in a policy that does not support it',
      detail: `${TYPE_NAMES[type]} cannot contain Principal or NotPrincipal (found in ${withPrincipal.length} statement(s)). Check the policy type.` })
  }
  if ((type === 'resource' || type === 'trust') && withPrincipal.length < parsed.statements.length) {
    out.push({ code: 'PRINCIPAL_MISSING', severity: 'medium', title: 'Statement without a Principal',
      detail: `Every statement in ${TYPE_NAMES[type]} needs a Principal or NotPrincipal (missing in ${parsed.statements.length - withPrincipal.length} statement(s)). Check the policy type.` })
  }

  // IAM treats a missing Version as 2008-10-17, where policy variables are plain text.
  const usesVariables = parsed.statements.some(s => JSON.stringify(s.raw).includes('${'))
  if (parsed.version && parsed.version !== '2012-10-17' && parsed.version !== '2008-10-17') {
    out.push({ code: 'UNKNOWN_VERSION', severity: 'medium', title: 'Unsupported Version',
      detail: `Version "${parsed.version}" is not valid. IAM accepts only 2012-10-17 or 2008-10-17.` })
  } else if (parsed.version !== '2012-10-17') {
    const which = parsed.version ? 'Version 2008-10-17' : 'No Version (treated as 2008-10-17)'
    out.push(usesVariables
      ? { code: 'OLD_VERSION_VARIABLES', severity: 'medium', title: 'Policy variables will not work',
          detail: `${which}: policy variables such as \${aws:username} are treated as literal text. Use Version 2012-10-17.` }
      : { code: 'OLD_VERSION', severity: 'low', title: 'Older policy language version',
          detail: `${which}. Use Version 2012-10-17 to support policy variables and newer features.` })
  }

  const sids = parsed.statements.map(s => s.sid).filter((s): s is string => !!s)
  const dupes = [...new Set(sids.filter((s, i) => sids.indexOf(s) !== i))]
  if (dupes.length) {
    out.push({ code: 'DUPLICATE_SID', severity: 'low', title: 'Duplicate Sid',
      detail: `Sid values should be unique within a policy: ${list(dupes)}.` })
  }

  const size = sizeLimit(type)
  if (size && parsed.charCount > size.limit) {
    out.push({ code: 'OVER_SIZE_LIMIT', severity: 'medium', title: 'Over the size limit',
      detail: `${parsed.charCount.toLocaleString('en-US')} characters as compact JSON, over the ${size.label} of ${size.limit.toLocaleString('en-US')}.` })
  }

  if (!opts.accountId) {
    const accounts = new Set<string>()
    for (const st of parsed.statements) {
      for (const e of [...principalEntries(st.raw.Principal), ...principalEntries(st.raw.NotPrincipal)]) {
        const a = principalAccount(e)
        if (a) accounts.add(a)
      }
    }
    if (accounts.size) {
      out.push({ code: 'PRINCIPAL_ACCOUNTS', severity: 'info', title: 'Principals from AWS accounts',
        detail: `Principals reference account(s) ${list([...accounts])}. Enter your account ID to flag cross-account access.` })
    }
  }

  return out
}

export function analyzePolicy(parsed: ParsedPolicy, opts: AnalyzeOptions = {}): Finding[] {
  const full = { ...opts, policyType: opts.policyType ?? detectPolicyType(parsed) }
  const partitions = policyPartitions(parsed)
  const findings = [
    ...parsed.statements.flatMap((st, i) => statementFindings(st, i + 1, { ...full, partitions })),
    ...policyFindings(parsed, full),
  ]
  return findings.sort((a, b) =>
    SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
    (a.statement ?? Infinity) - (b.statement ?? Infinity))
}

export function describeSubject(st: ParsedStatement): string {
  if (st.notPrincipal) return `Everyone except ${list(st.principals)}`
  const principals = principalEntries(st.raw.Principal)
  if (!principals.length) return 'Whoever this policy is attached to'
  if (principals.some(isPublic)) return 'Anyone (public access)'
  return `Each listed principal (${list(st.principals)})`
}
