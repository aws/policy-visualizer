// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi } from 'vitest'
import { parsePolicy } from './parse'
import { analyzePolicy } from './findings'
import { detectPolicyType } from './policyType'
import { Redactor, redactPolicy } from './redact'
import { diffPolicies, hasChanges } from './diff'
import { evaluateAccess, wildcardMatch } from './evaluate'
import { loadPolicyText, MAX_INPUT_CHARS, MAX_POLICY_CHARS } from './input'
import { describeParseError } from './parse'
import { findingsMarkdown } from './markdown'
import { buildOptimizedPolicy, buildPermissionRows } from './optimize'

// Fixtures use AWS documentation placeholders only: 111122223333 and
// 444455556666 for accounts, example-* for resource names.
const allow = (s: Record<string, unknown>) => ({ Effect: 'Allow', ...s })
// A Markdown line with its code spans removed: what a renderer would parse
// as Markdown.
const outsideCode = (line: string) => line.replace(/(`+)(?!`)[\s\S]*?(?<!`)\1(?!`)/g, '')
const policy = (...Statement: unknown[]) => parsePolicy({ Version: '2012-10-17', Statement })
const codes = (p: ReturnType<typeof policy>, policyType?: Parameters<typeof analyzePolicy>[1] extends infer O ? O extends { policyType?: infer T } ? T : never : never) =>
  analyzePolicy(p, { policyType }).map(f => f.code)

describe('condition pitfalls', () => {
  it('flags ForAllValues in an Allow unless the key is Null-checked', () => {
    const cond = { 'ForAllValues:StringEquals': { 'aws:TagKeys': ['Project'] } }
    expect(codes(policy(allow({ Action: 's3:PutObject', Resource: 'arn:aws:s3:::example-bucket/*', Condition: cond }))))
      .toContain('FORALLVALUES_MISSING_KEY')
    expect(codes(policy(allow({ Action: 's3:PutObject', Resource: 'arn:aws:s3:::example-bucket/*',
      Condition: { ...cond, Null: { 'aws:TagKeys': 'false' } } }))))
      .not.toContain('FORALLVALUES_MISSING_KEY')
  })

  it('flags ForAnyValue in a Deny', () => {
    expect(codes(policy({ Effect: 'Deny', Action: '*', Resource: '*',
      Condition: { 'ForAnyValue:StringEquals': { 'aws:TagKeys': ['Forbidden'] } } })))
      .toContain('DENY_FORANYVALUE_MISSING_KEY')
  })

  it('flags wildcards in StringEquals but not in StringLike or policy variables', () => {
    const stmt = (Condition: unknown) => policy(allow({ Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*', Condition }))
    expect(codes(stmt({ StringEquals: { 's3:prefix': 'home/*' } }))).toContain('WILDCARD_IN_EXACT_MATCH')
    expect(codes(stmt({ StringLike: { 's3:prefix': 'home/*' } }))).not.toContain('WILDCARD_IN_EXACT_MATCH')
    expect(codes(stmt({ StringEquals: { 's3:prefix': 'home/${aws:username}' } }))).not.toContain('WILDCARD_IN_EXACT_MATCH')
  })

  it('flags IfExists on an Allow', () => {
    expect(codes(policy(allow({ Action: 'ec2:RunInstances', Resource: '*',
      Condition: { StringEqualsIfExists: { 'ec2:InstanceType': 't3.micro' } } }))))
      .toContain('IFEXISTS_ALLOW')
  })
})

describe('policy types', () => {
  it('detects identity, resource, and trust policies from the contents', () => {
    expect(detectPolicyType(policy(allow({ Action: 's3:GetObject', Resource: '*' })))).toBe('identity')
    expect(detectPolicyType(policy(allow({ Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' })))).toBe('resource')
    expect(detectPolicyType(policy(allow({ Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' })))).toBe('trust')
  })

  it('detects SCPs and trust policies from the input wrapper', () => {
    const doc = { Version: '2012-10-17', Statement: [allow({ Action: '*', Resource: '*' })] }
    const scp = loadPolicyText(JSON.stringify({ Policy: { PolicySummary: { Name: 'example-scp' }, Content: JSON.stringify(doc) } }))
    expect(detectPolicyType(scp)).toBe('scp')
    const trustDoc = { Version: '2012-10-17', Statement: [allow({ Action: 'sts:AssumeRole' })] }
    expect(detectPolicyType(loadPolicyText(JSON.stringify({ Role: { RoleName: 'example-role', AssumeRolePolicyDocument: trustDoc } })))).toBe('trust')
    expect(detectPolicyType(loadPolicyText(JSON.stringify({ Roles: [{ AssumeRolePolicyDocument: trustDoc }] })))).toBe('trust')
  })

  it('does not take the policy type from words inside other keys', () => {
    const doc = { Version: '2012-10-17', Statement: [allow({ Action: '*', Resource: '*' })] }
    const wrapped = [
      // A CloudFormation logical ID is a name the author chose.
      { Resources: { AppRoleWithoutPermissionsBoundary: { Type: 'AWS::IAM::ManagedPolicy', Properties: { PolicyDocument: doc } } } },
      { Note: { PermissionsBoundary: doc } },
      { PermissionsBoundary: doc },
      { Example: { Policy: { Content: JSON.stringify(doc) } } },
      { 'Policy.Content': doc },
      { Policy: [{ Content: JSON.stringify(doc) }] },
      { Resources: { ExampleScpPolicy: { Properties: { Content: doc } } } },
    ]
    for (const w of wrapped) {
      const p = loadPolicyText(JSON.stringify(w))
      expect(detectPolicyType(p), JSON.stringify(w)).toBe('identity')
      expect(analyzePolicy(p).map(f => f.code), JSON.stringify(w)).toContain('ALL_ACTIONS')
    }
    // Only the key that holds the document decides a trust policy.
    const trust = { Version: '2012-10-17', Statement: [allow({ Action: 'sts:AssumeRole', Resource: '*' })] }
    expect(detectPolicyType(loadPolicyText(JSON.stringify({ Resources: { AssumeRolePolicyDocumentExample: { Properties: { PolicyDocument: trust } } } })))).toBe('identity')
  })

  it('does not flag the default FullAWSAccess SCP', () => {
    const fullAccess = policy(allow({ Action: '*', Resource: '*' }))
    expect(codes(fullAccess, 'identity')).toContain('ALL_ACTIONS')
    expect(codes(fullAccess, 'scp')).toEqual([])
  })

  it('uses the size limit for the policy type', () => {
    const resources = Array.from({ length: 160 }, (_, i) => `arn:aws:s3:::example-bucket-${i}/*`)
    const big = policy({ Effect: 'Deny', Action: 's3:DeleteObject', Resource: resources })
    expect(big.charCount).toBeGreaterThan(5120)
    expect(big.charCount).toBeLessThan(6144)
    expect(codes(big, 'scp')).toContain('OVER_SIZE_LIMIT')
    expect(codes(big, 'identity')).not.toContain('OVER_SIZE_LIMIT')
  })

  it('flags Principal where the type does not allow it, and missing Principal where it is required', () => {
    const withPrincipal = policy(allow({ Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' }))
    expect(codes(withPrincipal, 'identity')).toContain('PRINCIPAL_NOT_ALLOWED')
    const noPrincipal = policy(allow({ Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' }))
    expect(codes(noPrincipal, 'resource')).toContain('PRINCIPAL_MISSING')
  })
})

describe('redaction', () => {
  const parsed = policy(
    allow({ Sid: 'ExampleCorpRead', Principal: { AWS: 'arn:aws:iam::444455556666:role/example-role', Service: 'lambda.amazonaws.com' },
      Action: 's3:GetObject', Resource: ['arn:aws:s3:::example-bucket/reports/*', 'arn:aws:s3:::example-bucket'],
      Condition: { StringEquals: { 'aws:SourceVpce': 'vpce-example', 'aws:PrincipalAccount': '111122223333' }, Bool: { 'aws:SecureTransport': 'true' } } }),
    allow({ Action: 'dynamodb:Query', Resource: 'arn:aws:dynamodb:us-east-1:111122223333:table/example-table' }),
    allow({ Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::111122223333:root' }),
  )
  const red = redactPolicy(parsed)
  // Everything the diagram displays (raw is never displayed).
  const shown = JSON.stringify(red.statements.map(st => [st.sid, st.actions, st.resources, st.principals, st.conditions]))

  it('removes account IDs, names, Sids, and condition values', () => {
    for (const secret of ['111122223333', '444455556666', 'example-bucket', 'example-role', 'example-table', 'vpce-example', 'ExampleCorpRead']) {
      expect(shown).not.toContain(secret)
    }
  })

  it('keeps structure, actions, service principals, wildcards, and booleans', () => {
    expect(red.statements[0].resources).toEqual(['arn:aws:s3:::BUCKET-1/PATH-1/*', 'arn:aws:s3:::BUCKET-1'])
    expect(red.statements[0].principals).toContain('Service:lambda.amazonaws.com')
    expect(red.statements[0].principals).toContain('AWS:arn:aws:iam::ACCOUNT-1:role/NAME-1')
    expect(red.statements[1].resources).toEqual(['arn:aws:dynamodb:us-east-1:ACCOUNT-2:table/NAME-2'])
    expect(red.statements[2].resources).toEqual(['arn:aws:iam::ACCOUNT-2:root'])
    expect(red.statements[0].actions).toEqual(['s3:GetObject'])
    expect(red.statements[0].conditions.find(c => c.key === 'aws:SecureTransport')?.values).toEqual(['true'])
  })

  it('redacts identifiers that are not ARNs or account IDs', () => {
    const p = policy(
      { Effect: 'Allow', Principal: { CanonicalUser: '79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be' }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' },
      { Effect: 'Allow', Principal: { Federated: 'example-idp.example.com' }, Action: 'sts:AssumeRoleWithWebIdentity' },
      { Effect: 'Allow', Principal: { Federated: 'cognito-identity.amazonaws.com' }, Action: 'sts:AssumeRoleWithWebIdentity' },
      { Effect: 'Allow', Principal: { Federated: 'arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE0123' }, Action: 'sts:AssumeRoleWithWebIdentity' },
    )
    const red = redactPolicy(p)
    const shown = JSON.stringify(red.statements.map(st => st.principals))
    for (const secret of ['79a59df900b9', 'example-idp.example.com', '111122223333', 'EXAMPLE0123']) expect(shown).not.toContain(secret)
    expect(red.statements[0].principals).toEqual(['CanonicalUser:CANONICAL-1'])
    // Public identity providers are kept.
    expect(red.statements[2].principals).toEqual(['Federated:cognito-identity.amazonaws.com'])
  })

  it('redacts hostnames under amazonaws.com that carry a resource name, but keeps service names', () => {
    const p = policy({ Effect: 'Deny', Principal: '*', Action: 's3:*', Resource: '*', Condition: {
      StringEquals: { 'aws:Referer': 'example-bucket.s3.amazonaws.com', 'aws:CalledVia': 'cloudformation.amazonaws.com', 'aws:RequestedRegion': 'us-east-1' },
    } })
    const values = redactPolicy(p).statements[0].conditions.flatMap(c => c.values)
    expect(values).not.toContain('example-bucket.s3.amazonaws.com')
    expect(values).toContain('cloudformation.amazonaws.com')
    expect(values).toContain('us-east-1')
  })

  it('gives a value one placeholder even when it appears in different places', () => {
    const p = policy({ Effect: 'Allow', Principal: { Federated: 'example-idp.example.com' }, Action: 'sts:AssumeRoleWithWebIdentity',
      Condition: { StringEquals: { 'example-idp.example.com:aud': 'example-idp.example.com' } } })
    const r = new Redactor()
    const red = redactPolicy(p, r)
    const token = red.statements[0].principals[0].split(':')[1]
    expect(red.statements[0].conditions[0].values).toEqual([token])
    expect(r.text('issuer example-idp.example.com')).toBe(`issuer ${token}`)
  })

  it('keeps real Region names only', () => {
    const p = policy({ Effect: 'Deny', Action: 's3:*', Resource: '*', Condition: { StringEquals: {
      'aws:RequestedRegion': ['us-east-1', 'us-gov-west-1', 'ap-southeast-2', 'us-isob-east-1'], 'aws:PrincipalTag/env': 'my-secret-1' } } })
    const values = redactPolicy(p).statements[0].conditions.flatMap(c => c.values)
    expect(values).toEqual(expect.arrayContaining(['us-east-1', 'us-gov-west-1', 'ap-southeast-2', 'us-isob-east-1']))
    expect(values).not.toContain('my-secret-1')
  })

  it('redacts identifiers inside condition keys', () => {
    const oidc = 'oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE0123'
    const p = policy({ Effect: 'Allow', Principal: { Federated: `arn:aws:iam::111122223333:oidc-provider/${oidc}` }, Action: 'sts:AssumeRoleWithWebIdentity',
      Condition: { StringEquals: { [`${oidc}:sub`]: 'system:serviceaccount:example:example-sa', 'aws:ResourceTag/CostCenter': 'example', 'aws:SourceVpce': 'vpce-example', 'accounts.google.com:aud': 'example-client' } } })
    const r = new Redactor()
    const keys = redactPolicy(p, r).statements[0].conditions.map(c => c.key)
    expect(keys.join(' ')).not.toContain('EXAMPLE0123')
    expect(keys.join(' ')).not.toContain('CostCenter')
    expect(keys).toContain('aws:SourceVpce')
    expect(keys).toContain('accounts.google.com:aud')
    expect(keys.find(k => k.startsWith('aws:ResourceTag/'))).toMatch(/^aws:ResourceTag\/KEY-\d+$/)
    // Finding text that mentions the tag key is redacted the same way.
    expect(r.text('on aws:ResourceTag/CostCenter')).not.toContain('CostCenter')
  })

  it('redacts long numbers but keeps short ones', () => {
    const p = policy({ Effect: 'Deny', Action: 's3:*', Resource: '*', Condition: {
      StringEquals: { 'aws:PrincipalTag/employeeId': '1234567890' },
      NumericLessThan: { 's3:TlsVersion': '1.2', 'aws:MultiFactorAuthAge': '3600' } } })
    const values = redactPolicy(p).statements[0].conditions.flatMap(c => c.values)
    expect(values).not.toContain('1234567890')
    expect(values).toEqual(expect.arrayContaining(['1.2', '3600']))
  })

  it('replaces a malformed ARN, which has no parts to keep', () => {
    const p = policy(allow({ Action: 'sns:Publish', Resource: ['arn:aws:sns:us-east-1:111122223333', 'arn:aws:sns:us-east-1:111122223333:example-topic'] }))
    const r = new Redactor()
    const shown = redactPolicy(p, r).statements[0].resources
    expect(shown[0]).toMatch(/^NAME-\d+$/)
    expect(shown[1]).toMatch(/^arn:aws:sns:us-east-1:ACCOUNT-\d+:NAME-\d+$/)
    expect(r.text('see arn:aws:sns:us-east-1:111122223333 here')).toBe(`see ${shown[0]} here`)
  })

  it('keeps policy variables whole and wildcards anywhere inside ARNs', () => {
    const red = redactPolicy(policy(allow({ Action: 'iam:GetRole', Resource: [
      'arn:aws:iam::111122223333:role/${aws:username}',
      'arn:aws:s3:::example-bucket/${aws:PrincipalTag/team}/*',
      'arn:aws:iam::${aws:PrincipalAccount}:role/home-${aws:username}',
      'arn:aws:logs:us-east-1:111122223333:log-group:*-example-logs:*',
    ] }))).statements[0].resources
    expect(red).toEqual([
      'arn:aws:iam::ACCOUNT-1:role/${aws:username}',
      'arn:aws:s3:::BUCKET-1/${aws:PrincipalTag/KEY-1}/*',
      'arn:aws:iam::${aws:PrincipalAccount}:role/NAME-1${aws:username}',
      'arn:aws:logs:us-east-1:ACCOUNT-1:log-group:*NAME-2:*',
    ])
  })

  it('redacts ${...} text that is not a policy variable, and tag keys and defaults inside variables', () => {
    const r = new Redactor()
    const red = redactPolicy(policy(allow({ Action: 'iam:GetRole', Resource: [
      'arn:aws:iam::111122223333:role/${x:/example-secret-name/:y}',
      'arn:aws:s3:::example-bucket/x${example-payroll-db}',
      'arn:aws:iam::111122223333:role/${aws:PrincipalTag/example-project}',
      "arn:aws:iam::111122223333:role/${aws:ResourceTag/example-team, 'example-default'}",
      'arn:aws:s3:::example-bucket/${aws:username}/${*}${?}${$}',
    ] })), r).statements[0].resources
    const shown = red.join(' ')
    for (const secret of ['example-secret-name', 'example-payroll-db', 'example-project', 'example-team', 'example-default']) {
      expect(shown).not.toContain(secret)
    }
    expect(red[0]).toMatch(/^arn:aws:iam::ACCOUNT-1:role\/NAME-\d+:\/NAME-\d+\/:NAME-\d+$/)
    expect(red[1]).toMatch(/^arn:aws:s3:::BUCKET-1\/PATH-\d+$/)
    expect(red[2]).toMatch(/^arn:aws:iam::ACCOUNT-1:role\/\$\{aws:PrincipalTag\/KEY-\d+\}$/)
    expect(red[3]).toMatch(/^arn:aws:iam::ACCOUNT-1:role\/\$\{aws:ResourceTag\/KEY-\d+, 'VALUE-\d+'\}$/)
    expect(red[4]).toBe('arn:aws:s3:::BUCKET-1/${aws:username}/${*}${?}${$}')
    // The same tag key reads the same in finding text.
    expect(r.text('tag example-project')).not.toContain('example-project')
  })

  it('keeps only known policy variables, and the shape of other ${prefix:name} text', () => {
    const v = (body: string) => '$' + `{${body}}`
    const r = new Redactor()
    const red = redactPolicy(policy(allow({ Action: 'iam:GetRole', Resource: [
      `arn:aws:iam::111122223333:role/${v('example-payroll:example-db')}`,
      `arn:aws:iam::111122223333:role/${v('aws:example-secret')}`,
      `arn:aws:iam::111122223333:role/${v('aws:' + 'x'.repeat(505))}`,
      `arn:aws:iam::111122223333:role/${v('saml:' + 'y'.repeat(65))}`,
      `arn:aws:iam::111122223333:role/${v('aws:username')}/${v('AWS:UserName')}/${v('aws:PrincipalTag/example-team')}`,
      `arn:aws:s3:::example-bucket/${v('saml:sub')}/${v('sts:RoleSessionName')}/${v('accounts.google.com:sub')}`,
      `arn:aws:s3:::example-bucket/${v("aws:userid, 'us-east-1'")}/${v("aws:userid, 'example-default'")}`,
    ] })), r).statements[0].resources
    for (const secret of ['example-payroll', 'example-db', 'example-secret', 'xxxx', 'yyyy', 'example-team', 'example-default']) {
      expect(red.join(' ')).not.toContain(secret)
    }
    expect(red[0]).toMatch(/\/\$\{KEY-\d+:KEY-\d+\}$/)
    expect(red[1]).toMatch(/\/\$\{aws:KEY-\d+\}$/)
    expect(red[2]).toMatch(/\/\$\{aws:KEY-\d+\}$/)
    expect(red[3]).toMatch(/\/\$\{saml:KEY-\d+\}$/)
    expect(red[4]).toMatch(new RegExp('/\\$\\{aws:username\\}/\\$\\{AWS:UserName\\}/\\$\\{aws:PrincipalTag/KEY-\\d+\\}$'))
    expect(red[5]).toBe(`arn:aws:s3:::BUCKET-1/${v('saml:sub')}/${v('sts:RoleSessionName')}/${v('accounts.google.com:sub')}`)
    // Defaults follow the condition value rules: a Region stays.
    expect(red[6]).toMatch(new RegExp(`/\\$\\{aws:userid, 'us-east-1'\\}/\\$\\{aws:userid, 'VALUE-\\d+'\\}$`))
    // "aws" is never registered, so finding text keeps "arn:aws:".
    expect(r.text('arn:aws:s3:::example-bucket')).toBe('arn:aws:s3:::BUCKET-1')
  })

  it('keeps the "aws" account of AWS managed policies', () => {
    const red = redactPolicy(policy(allow({ Action: 'iam:GetPolicy', Resource: ['arn:aws:iam::aws:policy/ReadOnlyAccess', 'arn:aws:iam::example-account:role/x'] }))).statements[0].resources
    expect(red[0]).toMatch(/^arn:aws:iam::aws:policy\/NAME-\d+$/)
    expect(red[1]).toMatch(/^arn:aws:iam::NAME-\d+:role\/NAME-\d+$/)
  })

  it('stays fast on many "${" without a closing "}"', () => {
    const many = '$' + '{'
    const open = many.repeat(45000)
    const p = policy(allow({ Action: 's3:GetObject', Resource: [`arn:aws:iam::111122223333:role/${open}`, `arn:aws:s3:::example-bucket/${open}`],
      Condition: { StringEquals: { [`aws:ResourceTag/${open}`]: open } } }))
    const t0 = performance.now()
    redactPolicy(p)
    evaluateAccess(p, { action: 's3:GetObject', resource: 'arn:aws:s3:::example-bucket/x' })
    analyzePolicy(p)
    // Each of these took about 1.7 seconds before. Generous bound.
    expect(performance.now() - t0).toBeLessThan(1000)
  })

  it('redacts a very long value in free text without building a huge pattern', () => {
    const name = 'a'.repeat(90000)
    const r = new Redactor()
    redactPolicy(policy(allow({ Action: 's3:GetObject', Resource: `arn:aws:s3:::${name}` })), r)
    expect(r.text(`see ${name} and ${name}x`)).toBe(`see BUCKET-1 and ${name}x`)
  })

  it('redacts a non-numeric account field but keeps wildcards and variables there', () => {
    const red = redactPolicy(policy(allow({ Action: 'iam:GetRole', Resource: [
      'arn:aws:iam::example-account:role/x', 'arn:aws:iam::*:role/x', 'arn:aws:iam::${aws:PrincipalAccount}:role/x'] }))).statements[0].resources
    expect(red[0]).toMatch(/^arn:aws:iam::NAME-\d+:role\/NAME-\d+$/)
    expect(red[1]).toMatch(/^arn:aws:iam::\*:role\/NAME-\d+$/)
    expect(red[2]).toMatch(/^arn:aws:iam::\$\{aws:PrincipalAccount\}:role\/NAME-\d+$/)
  })

  it('replaces account IDs outside the account field of an ARN', () => {
    const shown = redactPolicy(policy(allow({ Action: 'sns:Publish', Resource: 'arn:aws:sns::us-east-1:111122223333:example-topic' }))).statements[0].resources[0]
    expect(shown).not.toContain('111122223333')
    expect(shown).not.toContain('example-topic')
  })

  it('redacts unknown element keys in finding text, but keeps near misses of real elements', () => {
    const p = parsePolicy({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*', ExampleCorpNote: 'x', Actions: 'y' }] })
    const r = new Redactor()
    redactPolicy(p, r)
    const details = analyzePolicy(p).filter(f => f.code === 'UNKNOWN_ELEMENT').map(f => r.text(f.detail))
    expect(details.join(' ')).not.toContain('ExampleCorpNote')
    expect(details).toContain('Statement 1 has "ELEMENT-1", which is not a policy element, so IAM rejects the policy.')
    expect(details).toContain('Statement 1 has "Actions", which is not a policy element, so IAM rejects the policy. Did you mean "Action"?')
  })

  it('does not rebuild the free text pattern for each new account ID it meets', () => {
    // A policy without these IDs, so every one of them is new to text().
    const r = new Redactor()
    redactPolicy(policy(allow({ Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' })), r)
    const ids = ['111122223333', '444455556666', '123456789012']
    const spy = vi.spyOn(globalThis, 'RegExp')
    try {
      const shown = ids.map(id => r.text(`see ${id}, arn:aws:s3:::example-bucket and x-${id}`))
      // One pattern for all calls. Before, each unseen ID added a value and
      // forced a rebuild, which took seconds over a large policy.
      expect(spy).toHaveBeenCalledTimes(1)
      expect(shown.join(' ')).not.toMatch(/\d{12}/)
      expect(shown[0]).toBe(`see ${r.account('111122223333')}, arn:aws:s3:::BUCKET-1 and x-${r.account('111122223333')}`)
    } finally {
      spy.mockRestore()
    }
  })

  it('redacts free text consistently with the policy', () => {
    const r = new Redactor()
    redactPolicy(parsed, r)
    expect(r.text('Grants access to principals in other AWS accounts: 444455556666.')).toBe('Grants access to principals in other AWS accounts: ACCOUNT-1.')
    expect(r.text('production example-bucket')).toBe('production BUCKET-1')
  })
})

describe('unknown policy elements', () => {
  it('reports a misspelled element instead of silently dropping it', () => {
    const p = parsePolicy({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Actions: ['s3:GetObject'], Resource: '*' }] })
    const f = analyzePolicy(p).find(x => x.code === 'UNKNOWN_ELEMENT')
    expect(f?.severity).toBe('medium')
    expect(f?.detail).toBe('Statement 1 has "Actions", which is not a policy element, so IAM rejects the policy. Did you mean "Action"?')
    // The statement is kept exactly as written.
    expect(p.statements[0].raw).toHaveProperty('Actions')
  })

  it('accepts the Id element and keeps it in the optimized policy', () => {
    const p = parsePolicy({ Version: '2012-10-17', Id: 'ExamplePolicyId', Statement: [{ Effect: 'Deny', Action: 's3:DeleteBucket', Resource: '*' }] })
    expect(analyzePolicy(p).map(x => x.code)).not.toContain('UNKNOWN_ELEMENT')
    expect(buildOptimizedPolicy(p, buildPermissionRows(p)).Id).toBe('ExamplePolicyId')
  })

  it('reports a "__proto__" key as an unknown element, without inheriting from it', () => {
    const p = loadPolicyText('{"Version":"2012-10-17","Statement":[{"Effect":"Deny","__proto__":{"Action":"s3:GetObject","Resource":"*"}}]}')
    expect(p.statements[0].actions).toEqual([])
    expect(({} as Record<string, unknown>).Action).toBeUndefined()
    expect(p.unknownElements).toEqual([{ statement: 1, key: '__proto__', suggestion: undefined }])
    expect(analyzePolicy(p).map(f => f.code)).toContain('UNKNOWN_ELEMENT')
    expect(loadPolicyText('{"Version":"2012-10-17","__proto__":{},"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}').unknownElements)
      .toEqual([{ statement: undefined, key: '__proto__', suggestion: undefined }])
  })

  it('rejects a "__proto__" key inside Condition or Principal instead of dropping it', () => {
    // Dropping the key would turn this conditional Deny into an unconditional one.
    for (const text of [
      '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"__proto__":"x"}}}]}',
      '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"__proto__":{"aws:SourceVpce":"vpce-example"}}}]}',
      '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"__proto__":"*"},"Action":"s3:GetObject","Resource":"*"}]}',
    ]) {
      let err: unknown
      try { loadPolicyText(text) } catch (e) { err = e }
      expect(describeParseError(err)).toMatch(/^Statement 1 has a "__proto__" key in (Condition|Principal)\. /)
    }
  })

  it('reports unknown top-level elements', () => {
    const p = parsePolicy({ Version: '2012-10-17', Statements: [], Statement: [{ Effect: 'Deny', Action: 's3:*', Resource: '*' }] })
    expect(analyzePolicy(p).find(x => x.code === 'UNKNOWN_ELEMENT')?.detail).toContain('The policy has "Statements"')
  })
})

describe('required elements', () => {
  it('flags a statement with no Action or NotAction, and never shows it as "*"', () => {
    const p = parsePolicy({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Resource: 'arn:aws:s3:::example-bucket/*' }] })
    expect(analyzePolicy(p).map(f => f.code)).toContain('MISSING_ACTION')
    const rows = buildPermissionRows(p)
    expect(rows.map(r => r.action)).toEqual(['(none)'])
    expect(rows[0].locked).toBeTruthy()
  })

  it('flags a missing Resource in identity policies but not in trust policies', () => {
    const noResource = parsePolicy({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject' }] })
    expect(analyzePolicy(noResource, { policyType: 'identity' }).map(f => f.code)).toContain('MISSING_RESOURCE')
    const trust = parsePolicy({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' }] })
    expect(analyzePolicy(trust).map(f => f.code)).not.toContain('MISSING_RESOURCE')
  })
})

describe('diffPolicies', () => {
  it('reports added and removed elements and new findings', () => {
    const before = policy(allow({ Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' }))
    const after = policy(allow({ Action: ['s3:GetObject', 's3:*'], Resource: 'arn:aws:s3:::example-bucket/*' }), { Effect: 'Deny', Action: 's3:DeleteBucket', Resource: '*' })
    const d = diffPolicies(before, after, analyzePolicy(before), analyzePolicy(after))
    expect(d.allowActions).toEqual({ added: ['s3:*'], removed: [] })
    expect(d.denyActions.added).toEqual(['s3:DeleteBucket'])
    expect(d.statementCount).toEqual({ before: 1, after: 2 })
    expect(d.newFindings.map(f => f.code)).toContain('SERVICE_WILDCARD')
    expect(hasChanges(d)).toBe(true)
  })

  const diff = (a: ReturnType<typeof policy>, b: ReturnType<typeof policy>) => diffPolicies(a, b, analyzePolicy(a), analyzePolicy(b))

  it('reports an action that moves to another statement', () => {
    const before = policy(allow({ Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-public/*' }), allow({ Action: 's3:DeleteObject', Resource: 'arn:aws:s3:::example-scratch/*' }))
    const after = policy(allow({ Action: ['s3:GetObject', 's3:DeleteObject'], Resource: 'arn:aws:s3:::example-public/*' }), allow({ Action: 's3:DeleteObject', Resource: 'arn:aws:s3:::example-scratch/*' }))
    const d = diff(before, after)
    expect(hasChanges(d)).toBe(true)
    expect(d.statements).toEqual({
      added: ['Allow; Action: s3:DeleteObject, s3:GetObject; Resource: arn:aws:s3:::example-public/*'],
      removed: ['Allow; Action: s3:GetObject; Resource: arn:aws:s3:::example-public/*'],
    })
    // The pooled element lists can't see it.
    expect(d.allowActions).toEqual({ added: [], removed: [] })
  })

  it('reports a Deny action, a principal, or a condition that moves to another statement', () => {
    const deny = (Action: string, Resource: string) => ({ Effect: 'Deny', Action, Resource })
    const denyBefore = policy(deny('s3:DeleteObject', 'arn:aws:s3:::example-bucket/*'), deny('s3:PutObject', 'arn:aws:s3:::example-logs/*'))
    const denyAfter = policy(deny('s3:PutObject', 'arn:aws:s3:::example-bucket/*'), deny('s3:DeleteObject', 'arn:aws:s3:::example-logs/*'))

    const grant = (AWS: string, Action: string) => allow({ Principal: { AWS }, Action, Resource: 'arn:aws:s3:::example-bucket/*' })
    const mine = 'arn:aws:iam::111122223333:root', other = 'arn:aws:iam::444455556666:root'
    const principalBefore = policy(grant(other, 's3:GetObject'), grant(mine, 's3:DeleteObject'))
    const principalAfter = policy(grant(mine, 's3:GetObject'), grant(other, 's3:DeleteObject'))

    const tls = { Bool: { 'aws:SecureTransport': 'true' } }
    const conditionBefore = policy(allow({ Action: 's3:PutObject', Resource: '*', Condition: tls }), allow({ Action: 's3:GetObject', Resource: '*' }))
    const conditionAfter = policy(allow({ Action: 's3:PutObject', Resource: '*' }), allow({ Action: 's3:GetObject', Resource: '*', Condition: tls }))

    for (const [a, b] of [[denyBefore, denyAfter], [principalBefore, principalAfter], [conditionBefore, conditionAfter]]) {
      const d = diff(a, b)
      expect(hasChanges(d)).toBe(true)
      expect(d.statements.added).toHaveLength(2)
      expect(d.statements.removed).toHaveLength(2)
    }
    expect(diff(principalBefore, principalAfter).statements.added)
      .toContain('Allow; Principal: AWS:arn:aws:iam::444455556666:root; Action: s3:DeleteObject; Resource: arn:aws:s3:::example-bucket/*')
  })

  it('reports a finding that moves to another statement', () => {
    const before = policy(allow({ Action: 's3:*', Resource: 'arn:aws:s3:::example-bucket/*' }), allow({ Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-logs/*' }))
    const after = policy(allow({ Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' }), allow({ Action: 's3:*', Resource: 'arn:aws:s3:::example-logs/*' }))
    const d = diff(before, after)
    const wildcard = (fs: typeof d.newFindings) => fs.filter(f => f.code === 'SERVICE_WILDCARD').map(f => f.statement)
    expect(wildcard(d.newFindings)).toEqual([2])
    expect(wildcard(d.resolvedFindings)).toEqual([1])
  })

  it('ignores Sid, statement order, and value order within a statement', () => {
    const a = policy(
      allow({ Sid: 'Read', Action: ['s3:GetObject', 's3:ListBucket'], Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*'] }),
      { Effect: 'Deny', Action: 's3:DeleteObject', Resource: '*', Condition: { StringNotEquals: { 'aws:SourceVpce': ['vpce-example1', 'vpce-example2'] } } },
    )
    const b = policy(
      { Effect: 'Deny', Action: ['s3:DeleteObject'], Resource: ['*'], Condition: { StringNotEquals: { 'aws:SourceVpce': ['vpce-example2', 'vpce-example1'] } } },
      allow({ Sid: 'ReadAll', Action: ['s3:ListBucket', 's3:GetObject'], Resource: ['arn:aws:s3:::example-bucket/*', 'arn:aws:s3:::example-bucket'] }),
    )
    const d = diff(a, b)
    expect(d.statements).toEqual({ added: [], removed: [] })
    expect(d.sids).toEqual({ added: ['ReadAll'], removed: ['Read'] })
    // Two copies of a statement are not the same policy text as one.
    const once = policy(allow({ Action: 's3:GetObject', Resource: '*' }), allow({ Action: 's3:PutObject', Resource: '*' }), allow({ Action: 's3:PutObject', Resource: '*' }))
    const twice = policy(allow({ Action: 's3:GetObject', Resource: '*' }), allow({ Action: 's3:GetObject', Resource: '*' }), allow({ Action: 's3:PutObject', Resource: '*' }))
    expect(hasChanges(diff(once, twice))).toBe(true)
  })

  it('lists changed statements in a form redaction covers', () => {
    const before = policy(allow({ Principal: { AWS: 'arn:aws:iam::444455556666:role/example-role' }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' }),
      allow({ Principal: { AWS: '444455556666' }, Action: 's3:PutObject', Resource: 'arn:aws:s3:::example-bucket/*', Condition: { StringEquals: { 'aws:SourceVpce': 'vpce-example' } } }))
    const after = policy(allow({ Principal: { AWS: '444455556666' }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' }),
      allow({ Principal: { AWS: 'arn:aws:iam::444455556666:role/example-role' }, Action: 's3:PutObject', Resource: 'arn:aws:s3:::example-bucket/*', Condition: { StringEquals: { 'aws:SourceVpce': 'vpce-example' } } }))
    const r = new Redactor()
    redactPolicy(before, r)
    redactPolicy(after, r)
    const d = diff(before, after)
    const shown = [...d.statements.added, ...d.statements.removed].map(t => r.text(t)).join('\n')
    expect(shown).toContain('Condition StringEquals aws:SourceVpce: VALUE-')
    for (const secret of ['444455556666', 'example-role', 'example-bucket', 'vpce-example']) expect(shown).not.toContain(secret)
  })

  it('reports no changes for identical policies, even with statements reordered', () => {
    const a = policy(allow({ Action: 's3:GetObject', Resource: '*' }), { Effect: 'Deny', Action: 'iam:*', Resource: '*' })
    const b = policy({ Effect: 'Deny', Action: 'iam:*', Resource: '*' }, allow({ Action: 's3:GetObject', Resource: '*' }))
    expect(hasChanges(diffPolicies(a, b, analyzePolicy(a), analyzePolicy(b)))).toBe(false)
  })
})

describe('evaluateAccess', () => {
  const p = policy(
    allow({ Sid: 'Read', Action: 's3:Get*', Resource: 'arn:aws:s3:::example-bucket/*' }),
    { Sid: 'NoSecrets', Effect: 'Deny', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/secret/*' },
  )

  it('allows a matching request', () => {
    const r = evaluateAccess(p, { action: 's3:getobject', resource: 'arn:aws:s3:::example-bucket/reports/a.csv' })
    expect(r.decision).toBe('allowed')
    expect(r.summary).toContain('Statement 1 (Read)')
  })

  it('lets an explicit Deny win', () => {
    expect(evaluateAccess(p, { action: 's3:GetObject', resource: 'arn:aws:s3:::example-bucket/secret/key.txt' }).decision).toBe('explicit-deny')
  })

  it('reports an implicit deny when nothing matches', () => {
    expect(evaluateAccess(p, { action: 's3:PutObject', resource: 'arn:aws:s3:::example-bucket/a' }).decision).toBe('implicit-deny')
  })

  it('treats NotAction as "everything except"', () => {
    const na = policy(allow({ NotAction: 'iam:*', Resource: '*' }))
    expect(evaluateAccess(na, { action: 'iam:CreateUser', resource: '*' }).decision).toBe('implicit-deny')
    expect(evaluateAccess(na, { action: 'ec2:RunInstances', resource: '*' }).decision).toBe('allowed')
  })

  it('reports conditions instead of evaluating them', () => {
    const c = policy(allow({ Action: 's3:GetObject', Resource: '*', Condition: { Bool: { 'aws:SecureTransport': 'true' } } }))
    expect(evaluateAccess(c, { action: 's3:GetObject', resource: 'arn:aws:s3:::example-bucket/a' }).decision).toBe('conditional')
  })

  it('mentions a Deny that might apply when the Allow is also conditional', () => {
    const c = policy(
      { Sid: 'ReadWithTls', Effect: 'Allow', Action: 's3:GetObject', Resource: '*', Condition: { Bool: { 'aws:SecureTransport': 'true' } } },
      { Sid: 'BlockOutsideVpce', Effect: 'Deny', Action: 's3:*', Resource: '*', Condition: { StringNotEquals: { 'aws:SourceVpce': 'vpce-example' } } },
    )
    const r = evaluateAccess(c, { action: 's3:GetObject', resource: 'arn:aws:s3:::example-bucket/a' })
    expect(r.decision).toBe('conditional')
    expect(r.summary).toBe('Allowed only if the conditions in Statement 1 (ReadWithTls) are met unless Statement 2 (BlockOutsideVpce) denies it.')
  })

  it('says the answer depends on the resource when none is entered and the statement is scoped', () => {
    const scoped = policy(allow({ Sid: 'OneBucket', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' }))
    const r = evaluateAccess(scoped, { action: 's3:GetObject' })
    expect(r.decision).toBe('depends-on-resource')
    expect(r.summary).toContain('Statement 1 (OneBucket) apply only to specific resources')
    // A statement on "*" still answers without a resource.
    expect(evaluateAccess(policy(allow({ Action: 's3:GetObject', Resource: '*' })), { action: 's3:GetObject' }).decision).toBe('allowed')
  })

  it('reports an implicit deny when only a scoped Deny is unresolved', () => {
    const denyOnly = policy({ Effect: 'Deny', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/secret/*' })
    expect(evaluateAccess(denyOnly, { action: 's3:GetObject' }).decision).toBe('implicit-deny')
  })

  it('needs a caller for principal-specific statements, and matches account principals', () => {
    const rp = policy(allow({ Principal: { AWS: 'arn:aws:iam::444455556666:root' }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' }))
    const req = { action: 's3:GetObject', resource: 'arn:aws:s3:::example-bucket/a' }
    expect(evaluateAccess(rp, req).decision).toBe('depends-on-principal')
    expect(evaluateAccess(rp, { ...req, principal: 'arn:aws:iam::444455556666:role/example-role' }).decision).toBe('allowed')
    expect(evaluateAccess(rp, { ...req, principal: 'arn:aws:iam::111122223333:role/example-role' }).decision).toBe('implicit-deny')
  })

  it('matches the sessions of a role named in Principal', () => {
    const rp = (Effect: string, AWS: string) => policy(
      allow({ Action: 's3:GetObject', Resource: '*' }),
      { Effect, Principal: { AWS }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' })
    const req = { action: 's3:GetObject', resource: 'arn:aws:s3:::example-bucket/x' }
    const session = 'arn:aws:sts::444455556666:assumed-role/example-role/example-session'
    const allowOnly = parsePolicy({ Version: '2012-10-17', Statement: [rp('Allow', 'arn:aws:iam::444455556666:role/example-role').statements[1].raw] })
    const r = evaluateAccess(allowOnly, { ...req, principal: session })
    expect(r.decision).toBe('allowed')
    expect(r.matches[0].notes.join(' ')).toContain('Matches arn:aws:iam::444455556666:role/example-role: the caller is a session of that role.')
    // A session ARN has the role name without its path.
    expect(evaluateAccess(rp('Deny', 'arn:aws:iam::444455556666:role/example-path/example-role'), { ...req, principal: session }).decision).toBe('explicit-deny')
    expect(evaluateAccess(rp('Deny', 'arn:aws:iam::444455556666:role/example-role'), { ...req, principal: session }).decision).toBe('explicit-deny')
    // Another role, account, or partition does not match.
    for (const other of ['arn:aws:sts::444455556666:assumed-role/example-other/example-session', 'arn:aws:sts::111122223333:assumed-role/example-role/example-session',
      'arn:aws-us-gov:sts::444455556666:assumed-role/example-role/example-session', 'arn:aws:sts::444455556666:assumed-role/example-role']) {
      expect(evaluateAccess(allowOnly, { ...req, principal: other }).decision, other).toBe('implicit-deny')
    }
  })

  it('does not give a definite answer for a role session against a role in NotPrincipal', () => {
    const p = policy(
      allow({ Action: 's3:GetObject', Resource: '*' }),
      { Effect: 'Deny', NotPrincipal: { AWS: ['arn:aws:iam::444455556666:role/example-role', 'arn:aws:iam::444455556666:root'] }, Action: 's3:GetObject', Resource: '*' })
    const req = { action: 's3:GetObject', resource: 'arn:aws:s3:::example-bucket/x' }
    // The account entry already excludes every principal in that account.
    expect(evaluateAccess(p, { ...req, principal: 'arn:aws:sts::444455556666:assumed-role/example-role/example-session' }).decision).toBe('allowed')
    const roleOnly = policy(
      allow({ Action: 's3:GetObject', Resource: '*' }),
      { Effect: 'Deny', NotPrincipal: { AWS: 'arn:aws:iam::444455556666:role/example-role' }, Action: 's3:GetObject', Resource: '*' })
    const r = evaluateAccess(roleOnly, { ...req, principal: 'arn:aws:sts::444455556666:assumed-role/example-role/example-session' })
    expect(r.decision).toBe('conditional')
    expect(r.summary).toBe('Allowed by Statement 1 unless Statement 2 denies it.')
    expect(r.matches[1].notes.join(' ')).toContain('is not certain')
    expect(evaluateAccess(roleOnly, { ...req, principal: 'arn:aws:iam::444455556666:role/example-role' }).decision).toBe('allowed')
    expect(evaluateAccess(roleOnly, { ...req, principal: 'arn:aws:sts::444455556666:assumed-role/example-other/example-session' }).decision).toBe('explicit-deny')
  })

  it('treats an Allow that matches only through a policy variable as conditional', () => {
    const v = policy(allow({ Sid: 'OwnHome', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/home/${aws:username}/*' }))
    const r = evaluateAccess(v, { action: 's3:GetObject', resource: 'arn:aws:s3:::example-bucket/home/someone/file' })
    expect(r.decision).toBe('conditional')
    expect(r.summary).toBe('Allowed only if the policy variables in Statement 1 (OwnHome) match the request.')
    expect(r.matches[0].notes.join(' ')).toContain('policy variables')
    // A resource outside the pattern can't match whatever the variable is.
    expect(evaluateAccess(v, { action: 's3:GetObject', resource: 'arn:aws:s3:::example-bucket/other/file' }).decision).toBe('implicit-deny')
  })

  it('reports a Deny that matches only through a policy variable as one that may deny, not an explicit deny', () => {
    const p = policy(
      allow({ Action: 's3:GetObject', Resource: '*' }),
      { Effect: 'Deny', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/home/${aws:username}/*' },
    )
    const r = evaluateAccess(p, { action: 's3:GetObject', resource: 'arn:aws:s3:::example-bucket/home/example-user/x' })
    expect(r.decision).toBe('conditional')
    expect(r.summary).toBe('Allowed by Statement 1 unless Statement 2 denies it.')
  })

  it('treats ${*}, ${?}, and ${$} as the literal characters', () => {
    const p = policy(
      allow({ Action: 's3:GetObject', Resource: '*' }),
      { Effect: 'Deny', Action: 's3:GetObject', Resource: ['arn:aws:s3:::example-bucket/${*}', 'arn:aws:s3:::example-bucket/q${?}', 'arn:aws:s3:::example-bucket/${$}{x}'] },
    )
    const check = (resource: string) => evaluateAccess(p, { action: 's3:GetObject', resource }).decision
    expect(check('arn:aws:s3:::example-bucket/secret.txt')).toBe('allowed')
    expect(check('arn:aws:s3:::example-bucket/*')).toBe('explicit-deny')
    expect(check('arn:aws:s3:::example-bucket/qa')).toBe('allowed')
    expect(check('arn:aws:s3:::example-bucket/q?')).toBe('explicit-deny')
    expect(check('arn:aws:s3:::example-bucket/${x}')).toBe('explicit-deny')
  })

  it('treats ${...} as plain text when the Version is not 2012-10-17', () => {
    const deny = { Effect: 'Deny', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/home/${aws:username}/*' }
    const old = parsePolicy({ Statement: [allow({ Action: 's3:GetObject', Resource: '*' }), deny] })
    const check = (resource: string) => evaluateAccess(old, { action: 's3:GetObject', resource })
    // Only a key under the literal "${aws:username}" folder is denied.
    expect(check('arn:aws:s3:::example-bucket/home/example-user/x').decision).toBe('allowed')
    expect(check('arn:aws:s3:::example-bucket/home/${aws:username}/x').decision).toBe('explicit-deny')
    expect(check('arn:aws:s3:::example-bucket/home/${aws:username}/x').matches[1].notes.join(' ')).toContain('plain text')
    // Whether "*" inside ${...} is still a wildcard here is not certain, so
    // a match that needs it is not a definite deny.
    const star = parsePolicy({ Version: '2008-10-17', Statement: [allow({ Action: 's3:GetObject', Resource: '*' }), { ...deny, Resource: 'arn:aws:s3:::example-bucket/${*}' }] })
    expect(evaluateAccess(star, { action: 's3:GetObject', resource: 'arn:aws:s3:::example-bucket/${x}' }).decision).toBe('conditional')
    expect(evaluateAccess(star, { action: 's3:GetObject', resource: 'arn:aws:s3:::example-bucket/${*}' }).decision).toBe('explicit-deny')
  })

  it('treats a NotResource with a policy variable as applying only for some requests', () => {
    const p = policy({ Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::example-bucket/home/${aws:username}/*' }, allow({ Action: 's3:GetObject', Resource: '*' }))
    expect(evaluateAccess(p, { action: 's3:GetObject', resource: 'arn:aws:s3:::example-bucket/home/example-user/x' }).decision).toBe('conditional')
    expect(evaluateAccess(p, { action: 's3:GetObject', resource: 'arn:aws:s3:::example-bucket/other/x' }).decision).toBe('explicit-deny')
  })
})

describe('wildcardMatch', () => {
  it('matches IAM wildcards', () => {
    expect(wildcardMatch('s3:Get*', 's3:GetObject')).toBe(true)
    expect(wildcardMatch('s3:Get?bject', 's3:GetObject')).toBe(true)
    expect(wildcardMatch('S3:GET*', 's3:getobject', true)).toBe(true)
    expect(wildcardMatch('S3:GET*', 's3:getobject')).toBe(false)
    expect(wildcardMatch('arn:aws:s3:::bucket/*', 'arn:aws:s3:::bucket')).toBe(false)
    expect(wildcardMatch('*', '')).toBe(true)
    expect(wildcardMatch('a*b*c', 'aXXbYYc')).toBe(true)
    expect(wildcardMatch('a*b*c', 'aXXbYY')).toBe(false)
  })

  it('stays fast on patterns that make regex engines backtrack (ReDoS)', () => {
    // A 20-wildcard pattern against a 1,000-character resource took minutes
    // with the old regex-based matcher.
    const p = policy(allow({ Action: 's3:GetObject', Resource: 'arn:aws:s3:::' + '*a'.repeat(20) + 'b' }))
    const t0 = performance.now()
    const r = evaluateAccess(p, { action: 's3:GetObject', resource: 'arn:aws:s3:::' + 'a'.repeat(1000) })
    expect(performance.now() - t0).toBeLessThan(100)
    expect(r.decision).toBe('implicit-deny')
  })
})

describe('input size limits', () => {
  it('rejects pasted text over the input limit', () => {
    let err: unknown
    try { loadPolicyText(' '.repeat(MAX_INPUT_CHARS + 1)) } catch (e) { err = e }
    expect(describeParseError(err)).toMatch(/^Input is [\d,]+ characters; the limit is 1,000,000\.$/)
  })

  it('rejects a policy over the policy limit with a clear message', () => {
    const resources = Array.from({ length: 4000 }, (_, i) => `arn:aws:s3:::example-bucket-${i}/*`)
    const text = JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: resources }] })
    expect(text.length).toBeGreaterThan(MAX_POLICY_CHARS)
    let err: unknown
    try { loadPolicyText(text) } catch (e) { err = e }
    expect(describeParseError(err)).toContain('this tool supports up to 100,000')
  })
})

describe('findingsMarkdown', () => {
  it('renders a table, escapes pipes, and applies the transform', () => {
    const findings = [{ code: 'X', severity: 'high' as const, title: 'A | B', detail: 'account 444455556666 | x', statement: 1, sid: 'S1' }]
    const md = findingsMarkdown(findings, { policyType: 'resource', statements: 1, charCount: 100, transform: t => t.replace('444455556666', 'ACCOUNT-1') })
    expect(md).toContain('| high | A \\| B | 1 \\(`S1`\\) | `account ACCOUNT-1 \\| x` |')
    expect(md).toContain('Policy type: Resource-based policy')
  })

  it('says when grant checks are off for the policy type', () => {
    const p = policy(allow({ Action: '*', Resource: '*' }))
    const detected = findingsMarkdown(analyzePolicy(p, { policyType: 'scp' }), { policyType: 'scp', typeDetected: true, statements: 1, charCount: p.charCount })
    expect(detected).toContain('> This policy was detected as an SCP or RCP from the input wrapper \\(Policy.Content, as in organizations describe-policy output\\).')
    expect(detected).toContain('Grant checks are off for this type')
    expect(detected).toContain('No issues found by the offline checks.')
    const picked = findingsMarkdown([], { policyType: 'boundary', statements: 1, charCount: p.charCount })
    expect(picked).toContain('> The policy type is set to a permissions boundary.')
    expect(findingsMarkdown([], { policyType: 'identity', typeDetected: true, statements: 1, charCount: p.charCount })).not.toContain('Grant checks are off')
  })

  it('escapes policy values so they cannot become links, images, or HTML', () => {
    // A hostile policy author controls Sids and action names.
    const p = policy({ Sid: 'x](https://example.invalid/track)![y', Effect: 'Allow', NotAction: '<img src=https://example.invalid/p>', Resource: '*' })
    const md = findingsMarkdown(analyzePolicy(p), { policyType: 'identity', statements: 1, charCount: p.charCount })
    const rows = md.split('\n').filter(l => l.startsWith('| high'))
    expect(rows.length).toBeGreaterThan(0)
    for (const row of rows) {
      // Policy values sit inside code spans; outside them, every bracket,
      // parenthesis, and angle bracket is backslash-escaped.
      expect(outsideCode(row)).not.toMatch(/(?<!\\)[[\]()<>!]/)
    }
    expect(md).toContain('`Allows every action except <img src=https://example.invalid/p>, including actions added to AWS in the future.`')
    expect(md).toContain('1 \\(`x](https://example.invalid/track)![y`\\)')
  })

  it('puts URLs, www. hosts, and @mentions from the policy in code spans', () => {
    const p = policy({ Sid: 'x', Effect: 'Allow', NotAction: '@example-user https://example.invalid/login www.example.invalid', Resource: '*' })
    const md = findingsMarkdown(analyzePolicy(p), { policyType: 'identity', statements: 1, charCount: p.charCount })
    const row = md.split('\n').find(l => l.includes('Allow with NotAction')) as string
    expect(row).toContain('| `Allows every action except @example-user https://example.invalid/login www.example.invalid, including actions added to AWS in the future.` |')
    for (const live of ['@example-user', 'https://', 'www.']) expect(outsideCode(row)).not.toContain(live)
  })

  it('uses a code span fence longer than any backtick run in the value', () => {
    const findings = [
      { code: 'X', severity: 'low' as const, title: 'T', detail: 'a `b` c', statement: 1, sid: '`edge`' },
      { code: 'Y', severity: 'low' as const, title: 'T', detail: 'two `` ticks', statement: 2 },
    ]
    const md = findingsMarkdown(findings, { policyType: 'identity', statements: 2, charCount: 10 })
    expect(md).toContain('| low | T | 1 \\(`` `edge` ``\\) | ``a `b` c`` |')
    expect(md).toContain('| low | T | 2 | ```two `` ticks``` |')
  })

  it('keeps a backslash before a pipe from ending the table cell', () => {
    // Synthetic values. Some renderers (micromark) read "\\" as one escape, so the "|" after it ends the cell.
    const cells = (row: string) => row.replace(/\\[\\|]/g, '  ').split('|').length - 2
    const findings = [{ code: 'X', severity: 'low' as const, title: 'T', detail: 'a\\| [x](https://example.invalid) b\\\\|c', statement: 1, sid: 'S\\|1' }]
    const row = findingsMarkdown(findings, { policyType: 'identity', statements: 1, charCount: 10 }).split('\n').find(l => l.startsWith('| low')) as string
    expect(cells(row)).toBe(4)
  })

  it('says so when there are no findings', () => {
    expect(findingsMarkdown([], { policyType: 'identity', statements: 1, charCount: 10, sizeLimit: 6144 }))
      .toContain('No issues found by the offline checks.')
  })
})
