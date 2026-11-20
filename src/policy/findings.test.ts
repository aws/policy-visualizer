// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { parsePolicy } from './parse'
import { analyzePolicy, describeSubject, type AnalyzeOptions } from './findings'

// Fixtures use AWS documentation placeholders only. 111122223333 stands for
// "your" account and 444455556666 for another account.
const MINE = '111122223333'
const OTHER = '444455556666'

function codes(policy: unknown, opts?: AnalyzeOptions) {
  return analyzePolicy(parsePolicy(policy), opts).map(f => f.code)
}
function stmt(s: Record<string, unknown>) {
  return { Version: '2012-10-17', Statement: [{ Effect: 'Allow', ...s }] }
}

describe('principal checks', () => {
  it('flags public access with no conditions as high', () => {
    for (const Principal of ['*', { AWS: '*' }]) {
      const f = analyzePolicy(parsePolicy(stmt({ Principal, Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' })))
      expect(f.find(x => x.code === 'PUBLIC_PRINCIPAL')?.severity).toBe('high')
    }
  })

  it('downgrades public access to medium when conditions are present', () => {
    expect(codes(stmt({
      Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*',
      Condition: { StringEquals: { 'aws:SourceVpce': 'vpce-example' } },
    }))).toContain('PUBLIC_PRINCIPAL_CONDITIONAL')
  })

  it('names the condition keys a downgrade is based on', () => {
    const f = analyzePolicy(parsePolicy(stmt({
      Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*',
      Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-exampleorgid' }, Bool: { 'aws:SecureTransport': 'true' } },
    })))
    expect(f.find(x => x.code === 'PUBLIC_PRINCIPAL_CONDITIONAL')?.detail).toContain('aws:PrincipalOrgID')
  })

  it('keeps public access high when the conditions do not limit who can call', () => {
    const conditions = [
      { Bool: { 'aws:SecureTransport': 'true' } },
      { DateLessThan: { 'aws:CurrentTime': '2030-01-01T00:00:00Z' } },
      // Everyone outside the organization, or callers with no org at all.
      { StringNotEquals: { 'aws:PrincipalOrgID': 'o-exampleorgid' } },
      { StringEqualsIfExists: { 'aws:PrincipalOrgID': 'o-exampleorgid' } },
      { 'ForAllValues:StringLike': { 'aws:PrincipalOrgPaths': ['o-exampleorgid/*'] } },
      { StringLike: { 'aws:PrincipalArn': '*' } },
      { IpAddress: { 'aws:SourceIp': '0.0.0.0/0' } },
      // Wildcards in the account position, or everywhere.
      { StringLike: { 'aws:PrincipalArn': 'arn:*' } },
      { StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:*' } },
      { ArnLike: { 'aws:SourceArn': 'arn:*' } },
      { ArnLike: { 'aws:SourceArn': '*:*' } },
      { ArnEquals: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/example-role' } },
      { StringLike: { 'aws:PrincipalOrgID': 'o-*' } },
      // A policy variable compares the caller with itself.
      { StringEquals: { 'aws:PrincipalOrgID': '$' + '{aws:PrincipalOrgID}' } },
      // Ranges that together, or alone, cover most of the internet.
      { IpAddress: { 'aws:SourceIp': ['0.0.0.0/1', '128.0.0.0/1'] } },
      { IpAddress: { 'aws:SourceIp': '0.0.0.0/0 ' } },
      { IpAddress: { 'aws:SourceIp': '10.0.0.0/7' } },
      { IpAddress: { 'aws:SourceIp': '2001:db8::/15' } },
      // IPv4-mapped and IPv4-compatible IPv6 ranges that cover all of IPv4.
      { IpAddress: { 'aws:SourceIp': '::ffff:0.0.0.0/96' } },
      { IpAddress: { 'aws:SourceIp': '::ffff:0:0/96' } },
      { IpAddress: { 'aws:SourceIp': '::0.0.0.0/96' } },
      { IpAddress: { 'aws:SourceIp': '::ffff:10.0.0.0/103' } },
      // Values that are not addresses or have an invalid prefix.
      { IpAddress: { 'aws:SourceIp': '....' } },
      { IpAddress: { 'aws:SourceIp': 'abc.def' } },
      { IpAddress: { 'aws:SourceIp': '/999' } },
      { IpAddress: { 'aws:SourceIp': '300.0.0.0/8' } },
      { IpAddress: { 'aws:SourceIp': '192.0.2.0/33' } },
      { IpAddress: { 'aws:SourceIp': '2001:db8::/129' } },
      { IpAddress: { 'aws:SourceIp': '2001:db8:::1' } },
    ]
    for (const Condition of conditions) {
      const f = analyzePolicy(parsePolicy(stmt({ Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*', Condition })))
      const pub = f.find(x => x.code === 'PUBLIC_PRINCIPAL')
      expect(pub?.severity, JSON.stringify(Condition)).toBe('high')
      expect(pub?.detail).toContain('do not limit who can call')
      expect(f.map(x => x.code)).not.toContain('PUBLIC_PRINCIPAL_CONDITIONAL')
    }
  })

  it('still downgrades conditions that pin the caller down', () => {
    const conditions = [
      { StringEquals: { 'aws:PrincipalOrgID': 'o-exampleorgid' } },
      { ArnLike: { 'aws:PrincipalArn': `arn:aws:iam::${OTHER}:role/*` } },
      { 'ForAnyValue:StringLike': { 'aws:PrincipalOrgPaths': 'o-exampleorgid/r-ab12/*' } },
      { IpAddress: { 'aws:SourceIp': ['192.0.2.0/24', '2001:db8::/32', '192.0.2.1', '::ffff:192.0.2.0/120'] } },
    ]
    for (const Condition of conditions) {
      const f = analyzePolicy(parsePolicy(stmt({ Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*', Condition })))
      expect(f.find(x => x.code === 'PUBLIC_PRINCIPAL_CONDITIONAL')?.severity, JSON.stringify(Condition)).toBe('medium')
    }
  })

  it('does not flag a public principal in a Deny statement', () => {
    expect(codes({ Version: '2012-10-17', Statement: [{
      Effect: 'Deny', Principal: '*', Action: 's3:*', Resource: '*',
      Condition: { Bool: { 'aws:SecureTransport': false } },
    }] })).not.toContain('PUBLIC_PRINCIPAL')
  })

  it('flags Allow with NotPrincipal', () => {
    expect(codes(stmt({ NotPrincipal: { AWS: `arn:aws:iam::${MINE}:root` }, Action: 's3:GetObject', Resource: '*' })))
      .toContain('ALLOW_NOT_PRINCIPAL')
  })

  it('flags other accounts only when the user gives their account ID', () => {
    const policy = stmt({
      Principal: { AWS: [`arn:aws:iam::${MINE}:role/example-role`, `arn:aws:iam::${OTHER}:root`, OTHER] },
      Action: 'sts:AssumeRole',
    })
    const withId = analyzePolicy(parsePolicy(policy), { accountId: MINE })
    const cross = withId.find(f => f.code === 'CROSS_ACCOUNT_PRINCIPAL')
    expect(cross?.detail).toContain(OTHER)
    expect(cross?.detail).not.toContain(MINE)

    const withoutId = analyzePolicy(parsePolicy(policy))
    expect(withoutId.map(f => f.code)).not.toContain('CROSS_ACCOUNT_PRINCIPAL')
    expect(withoutId.find(f => f.code === 'PRINCIPAL_ACCOUNTS')?.detail).toContain(OTHER)
  })

  it('does not report cross-account access for principals in your own account', () => {
    expect(codes(stmt({ Principal: { AWS: `arn:aws:iam::${MINE}:root` }, Action: 'sts:AssumeRole' }), { accountId: MINE }))
      .not.toContain('CROSS_ACCOUNT_PRINCIPAL')
  })

  it('ignores service principals for account checks', () => {
    expect(codes(stmt({ Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' }), { accountId: MINE }))
      .toEqual([])
  })
})

describe('action and resource checks', () => {
  it('flags Action "*" and service wildcards', () => {
    expect(codes(stmt({ Action: '*', Resource: '*' }))).toContain('ALL_ACTIONS')
    expect(codes(stmt({ Action: 's3:*', Resource: 'arn:aws:s3:::example-bucket' }))).toContain('SERVICE_WILDCARD')
  })

  it('flags sensitive actions but not read-only IAM calls or role assumption', () => {
    expect(codes(stmt({ Action: ['iam:CreateUser', 'kms:Decrypt'], Resource: '*' }))).toContain('SENSITIVE_ACTIONS')
    expect(codes(stmt({ Action: ['iam:GetRole', 'iam:ListRoles'], Resource: '*' }))).not.toContain('SENSITIVE_ACTIONS')
    // IAM action names are case-insensitive.
    expect(codes(stmt({ Action: 's3:putbucketpolicy', Resource: 'arn:aws:s3:::example-bucket' }))).toContain('SENSITIVE_ACTIONS')
    expect(codes(stmt({ Action: 'S3:PutObjectAcl', Resource: 'arn:aws:s3:::example-bucket/*' }))).toContain('SENSITIVE_ACTIONS')
    expect(codes(stmt({ Action: 'sts:AssumeRole', Resource: `arn:aws:iam::${MINE}:role/example-role` }))).not.toContain('SENSITIVE_ACTIONS')
  })

  it('flags wildcard patterns that cover sensitive actions', () => {
    for (const Action of ['iam:*', 'iam:*Role', 'iam:P*', 's3:PutBucket*', 'kms:*', 'organizations:Leave*', 'IAM:Create?ser']) {
      expect(codes(stmt({ Action, Resource: '*' })), Action).toContain('SENSITIVE_ACTIONS')
    }
    // Names missing from the built-in list are still covered by the service
    // rule: any KMS action, and IAM or Organizations writes.
    for (const Action of ['kms:Rotate*', 'kms:*CustomKeyStore', 'kms:Gen*Random', 'iam:Tag*Policy', 'iam:*CloudFrontPublicKey', 'iam:Generate*', 'iam:Simulate*', 'iam:G*']) {
      expect(codes(stmt({ Action, Resource: '*' })), Action).toContain('SENSITIVE_ACTIONS')
    }
    for (const Action of ['iam:Get*', 'iam:List*', 'organizations:Describe*', 's3:Get*', 'sts:Assume*']) {
      expect(codes(stmt({ Action, Resource: '*' })), Action).not.toContain('SENSITIVE_ACTIONS')
    }
  })

  it('flags patterns that cover iam:PassRole on any role', () => {
    for (const Action of ['iam:*', 'iam:*Role', 'iam:P*', 'iam:Pass*', 'iam:PassRol?', '*']) {
      const f = analyzePolicy(parsePolicy(stmt({ Action, Resource: '*' })))
      expect(f.find(x => x.code === 'PASSROLE_ANY_ROLE')?.severity, Action).toBe('high')
    }
    expect(codes(stmt({ Action: 'iam:Put*', Resource: '*' }))).not.toContain('PASSROLE_ANY_ROLE')
    // A pattern that covers only PassRole is not reported twice.
    expect(codes(stmt({ Action: 'iam:Pass*', Resource: '*' }))).not.toContain('SENSITIVE_ACTIONS')
    // Action "*" is reported as ALL_ACTIONS, not as a list of sensitive actions.
    expect(codes(stmt({ Action: '*', Resource: '*' }))).not.toContain('SENSITIVE_ACTIONS')
  })

  it('flags Allow with NotAction and NotResource', () => {
    expect(codes(stmt({ NotAction: 'iam:*', Resource: '*' }))).toContain('ALLOW_NOT_ACTION')
    expect(codes(stmt({ Action: 's3:GetObject', NotResource: 'arn:aws:s3:::example-bucket/*' }))).toContain('ALLOW_NOT_RESOURCE')
  })

  it('flags iam:PassRole on any role, and lowers severity with iam:PassedToService', () => {
    const open = analyzePolicy(parsePolicy(stmt({ Action: 'iam:PassRole', Resource: '*' })))
    expect(open.find(f => f.code === 'PASSROLE_ANY_ROLE')?.severity).toBe('high')
    const scoped = analyzePolicy(parsePolicy(stmt({
      Action: 'iam:PassRole', Resource: '*',
      Condition: { StringEquals: { 'iam:PassedToService': 'lambda.amazonaws.com' } },
    })))
    expect(scoped.find(f => f.code === 'PASSROLE_ANY_ROLE')?.severity).toBe('medium')
    expect(open.map(f => f.code)).not.toContain('SENSITIVE_ACTIONS')
    expect(codes(stmt({ Action: 'iam:PassRole', Resource: `arn:aws:iam::${MINE}:role/example-role` })))
      .not.toContain('PASSROLE_ANY_ROLE')
    // Wildcard role ARNs are "any role" too.
    // OTHER is not the matcher's internal probe account, so this covers
    // every role in an arbitrary specific account too.
    for (const Resource of ['arn:aws:iam::*:role/*', `arn:aws:iam::${MINE}:role/*`, `arn:aws:iam::${OTHER}:role/*`, 'arn:aws:iam::*:*', 'arn:aws-us-gov:iam::*:role/*']) {
      const f = analyzePolicy(parsePolicy(stmt({ Action: 'iam:PassRole', Resource })))
      expect(f.find(x => x.code === 'PASSROLE_ANY_ROLE')?.severity, Resource).toBe('high')
    }
    expect(codes(stmt({ Action: 'iam:PassRole', Resource: `arn:aws:iam::${MINE}:role/service/example-*` })))
      .not.toContain('PASSROLE_ANY_ROLE')
  })

  it('flags iam:PassRole with a NotResource that leaves roles to pass', () => {
    for (const NotResource of [`arn:aws:iam::${MINE}:role/OrgAdmin`, `arn:aws:iam::${MINE}:role/*`, `arn:aws:iam::${OTHER}:role/*`,
      'arn:aws:iam::*:role/zz*', 'arn:aws:iam::*:role/*/*', 'arn:aws:iam::*:role/??*', 'arn:aws:iam::*:user/*']) {
      const f = analyzePolicy(parsePolicy(stmt({ Action: 'iam:PassRole', NotResource })))
      const pass = f.find(x => x.code === 'PASSROLE_ANY_ROLE')
      expect(pass?.severity, NotResource).toBe('high')
      expect(pass?.detail, NotResource).toContain(`every role except ${NotResource}`)
      // PASSROLE_ANY_ROLE already says it, as for Resource "*".
      expect(f.map(x => x.code), NotResource).not.toContain('SENSITIVE_ACTIONS')
      expect(f.map(x => x.code), NotResource).toContain('ALLOW_NOT_RESOURCE')
    }
    const scoped = analyzePolicy(parsePolicy(stmt({ Action: 'iam:PassRole', NotResource: `arn:aws:iam::${MINE}:role/OrgAdmin`,
      Condition: { StringEquals: { 'iam:PassedToService': 'lambda.amazonaws.com' } } })))
    expect(scoped.find(f => f.code === 'PASSROLE_ANY_ROLE')?.severity).toBe('medium')
    // A NotResource that excludes every role leaves none to pass.
    for (const NotResource of ['*', 'arn:aws:iam::*:role/*', 'arn:aws:iam::*:*', 'arn:aws:iam::*:role/?*', 'arn:*:iam::*:role*']) {
      expect(codes(stmt({ Action: 'iam:PassRole', NotResource })), NotResource).not.toContain('PASSROLE_ANY_ROLE')
    }
  })

  it('tests a NotResource against aws roles and the roles of every partition the policy names', () => {
    // Excluding the roles of another partition leaves every aws role.
    for (const NotResource of ['arn:aws-cn:iam::*:role/*', 'arn:aws-us-gov:iam::*:role/*', 'arn:aws-iso:iam::*:role/*',
      ['arn:aws-cn:iam::*:role/*', 'arn:aws-us-gov:iam::*:role/*']]) {
      const f = analyzePolicy(parsePolicy(stmt({ Action: 'iam:PassRole', NotResource })))
      expect(f.find(x => x.code === 'PASSROLE_ANY_ROLE')?.severity, String(NotResource)).toBe('high')
    }
    // Every partition named needs its roles excluded too.
    expect(codes(stmt({ Action: 'iam:PassRole', NotResource: ['arn:aws:iam::*:role/*', 'arn:aws-cn:iam::*:role/example-*'] }))).toContain('PASSROLE_ANY_ROLE')
    // Entries that each match some probes with a literal do not add up to every role.
    expect(codes(stmt({ Action: 'iam:PassRole', NotResource: ['arn:aws:iam::*:role/x', 'arn:aws:iam::*:role/Q7/k', 'arn:aws:iam::*:role/_+=,.@-'] }))).toContain('PASSROLE_ANY_ROLE')
    expect(codes({ Version: '2012-10-17', Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', NotResource: 'arn:aws:iam::*:role/*' },
      { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws-us-gov:s3:::example-bucket/*' }] })).toContain('PASSROLE_ANY_ROLE')
    for (const NotResource of ['arn:*:iam::*:role/*', ['arn:aws:iam::*:role/*', 'arn:aws-cn:iam::*:role/*'], ['arn:aws-cn:iam::*:*', 'arn:aws:iam::*:*']]) {
      expect(codes(stmt({ Action: 'iam:PassRole', NotResource })), String(NotResource)).not.toContain('PASSROLE_ANY_ROLE')
    }
  })

  it('names the pattern that allows all actions', () => {
    const f = analyzePolicy(parsePolicy(stmt({ Action: ['s3:GetObject', '**'], Resource: '*' })))
    expect(f.find(x => x.code === 'ALL_ACTIONS')?.detail).toBe('Action "**" allows every action in every AWS service.')
    expect(analyzePolicy(parsePolicy(stmt({ Action: '*', Resource: '*' }))).find(x => x.code === 'ALL_ACTIONS')?.detail)
      .toBe('Action "*" allows every action in every AWS service.')
  })

  it('flags every spelling of a service-wide action wildcard', () => {
    for (const Action of ['ec2:*?', 'ec2:**', 'ec2:?*', 'sts:*?', 'lambda:**', 'EC2:*']) {
      expect(codes(stmt({ Action, Resource: '*' })), Action).toContain('SERVICE_WILDCARD')
      expect(codes(stmt({ Action, Resource: `arn:aws:ec2:us-east-1:${MINE}:instance/i-example` })), Action).toContain('SERVICE_WILDCARD')
    }
    for (const Action of ['ec2:Describe*', 'ec2:*Instances', 'ec2:?', 'ec2:', 'ec2:*:x']) {
      expect(codes(stmt({ Action, Resource: '*' })), Action).not.toContain('SERVICE_WILDCARD')
    }
    // Spellings of Action "*" are all actions, not a list of sensitive ones.
    for (const Action of ['**', '*?', '?*', '*:*', '*:**']) {
      const found = codes(stmt({ Action, Resource: '*' }))
      expect(found, Action).toContain('ALL_ACTIONS')
      expect(found, Action).not.toContain('SENSITIVE_ACTIONS')
      expect(found, Action).not.toContain('ALL_RESOURCES')
    }
    // A long run of wildcards is checked in linear time.
    const t0 = performance.now()
    codes(stmt({ Action: [`ec2:${'*?'.repeat(40000)}x`, `ec2:${'*'.repeat(80000)}`], Resource: '*' }))
    expect(performance.now() - t0).toBeLessThan(1000)
  })

  it('flags service-wide resource ARNs but not account-scoped ones', () => {
    expect(codes(stmt({ Action: 's3:GetObject', Resource: 'arn:aws:s3:::*' }))).toContain('SERVICE_WIDE_RESOURCES')
    expect(codes(stmt({ Action: 's3:GetObject', Resource: 'arn:aws:s3:::*/*' }))).toContain('SERVICE_WIDE_RESOURCES')
    expect(codes(stmt({ Action: 'dynamodb:Query', Resource: 'arn:aws:dynamodb:*:*:table/*' }))).toContain('SERVICE_WIDE_RESOURCES')
    expect(codes(stmt({ Action: 'dynamodb:Query', Resource: `arn:aws:dynamodb:us-east-1:${MINE}:table/*` }))).not.toContain('SERVICE_WIDE_RESOURCES')
    expect(codes(stmt({ Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' }))).not.toContain('SERVICE_WIDE_RESOURCES')
  })

  it('flags S3 object actions on bucket ARNs and bucket actions on object ARNs', () => {
    expect(codes(stmt({ Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket' }))).toContain('S3_OBJECT_ACTION_ON_BUCKET')
    expect(codes(stmt({ Action: 's3:ListBucket', Resource: 'arn:aws:s3:::example-bucket/*' }))).toContain('S3_BUCKET_ACTION_ON_OBJECT')
  })

  it('does not flag S3 statements that include both bucket and object ARNs', () => {
    const found = codes(stmt({
      Action: ['s3:GetObject', 's3:ListBucket'],
      Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*'],
    }))
    expect(found).not.toContain('S3_OBJECT_ACTION_ON_BUCKET')
    expect(found).not.toContain('S3_BUCKET_ACTION_ON_OBJECT')
  })

  it('does not flag anything for a well-scoped Allow or for Deny statements', () => {
    expect(codes(stmt({ Action: 'dynamodb:Query', Resource: `arn:aws:dynamodb:us-east-1:${MINE}:table/example-table` }))).toEqual([])
    expect(codes({ Version: '2012-10-17', Statement: [{ Effect: 'Deny', Action: '*', Resource: '*' }] })).toEqual([])
  })
})

describe('policy-level checks', () => {
  it('flags a missing or old Version, and raises severity when policy variables are used', () => {
    expect(codes({ Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' }] }))
      .toContain('OLD_VERSION')
    expect(codes({ Version: '2008-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/${aws:username}/*' }] }))
      .toContain('OLD_VERSION_VARIABLES')
    expect(codes({ Version: '2020-01-01', Statement: [{ Effect: 'Deny', Action: '*', Resource: '*' }] }))
      .toContain('UNKNOWN_VERSION')
  })

  it('flags duplicate Sids', () => {
    expect(codes({ Version: '2012-10-17', Statement: [
      { Sid: 'Same', Effect: 'Deny', Action: 's3:DeleteObject', Resource: '*' },
      { Sid: 'Same', Effect: 'Deny', Action: 's3:DeleteBucket', Resource: '*' },
    ] })).toContain('DUPLICATE_SID')
  })

  it('flags policies over the managed policy size limit', () => {
    const resources = Array.from({ length: 200 }, (_, i) => `arn:aws:s3:::example-bucket-${i}/*`)
    const parsed = parsePolicy(stmt({ Action: 's3:GetObject', Resource: resources }))
    expect(parsed.charCount).toBeGreaterThan(6144)
    expect(analyzePolicy(parsed).map(f => f.code)).toContain('OVER_SIZE_LIMIT')
  })

  it('counts compact JSON: white space between elements is ignored, inside values it counts', () => {
    expect(parsePolicy(JSON.parse('{ "Statement" : { "Effect" : "Deny" } }')).charCount)
      .toBe('{"Statement":{"Effect":"Deny"}}'.length)
    // Spaces inside a value are part of the policy and must not be dropped.
    const withSpaces = { Statement: { Effect: 'Deny', Action: 's3:*', Resource: '*', Condition: { StringEquals: { 'aws:PrincipalTag/team': 'data platform team' } } } }
    expect(parsePolicy(withSpaces).charCount).toBe(JSON.stringify(withSpaces).length)
  })

  it('sorts findings by severity', () => {
    const f = analyzePolicy(parsePolicy({ Statement: [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: '*' }] }))
    const order = ['high', 'medium', 'low', 'info']
    expect(f.map(x => order.indexOf(x.severity))).toEqual([...f.map(x => order.indexOf(x.severity))].sort((a, b) => a - b))
  })
})

describe('describeSubject', () => {
  const subject = (s: Record<string, unknown>) => describeSubject(parsePolicy(stmt(s)).statements[0])
  it('names who the statement applies to', () => {
    expect(subject({ Action: 's3:GetObject', Resource: '*' })).toBe('Whoever this policy is attached to')
    expect(subject({ Principal: '*', Action: 's3:GetObject', Resource: '*' })).toBe('Anyone (public access)')
    expect(subject({ Principal: { AWS: `arn:aws:iam::${MINE}:root` }, Action: 'sts:AssumeRole' }))
      .toBe(`Each listed principal (AWS:arn:aws:iam::${MINE}:root)`)
    expect(subject({ NotPrincipal: { AWS: `arn:aws:iam::${MINE}:root` }, Action: 's3:GetObject', Resource: '*' }))
      .toBe(`Everyone except AWS:arn:aws:iam::${MINE}:root`)
  })
})
