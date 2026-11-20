// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { parsePolicy } from './parse'
import { buildOptimizedPolicy, buildPermissionRows, buildSummaryRows, MAX_TABLE_ROWS, permissionRowCount, versionWarning, type PermissionRow } from './optimize'

// Fixtures use AWS documentation placeholders only.
function markNeeded(rows: PermissionRow[], pick: (r: PermissionRow) => boolean) {
  return rows.map(r => (pick(r) ? { ...r, status: 'needed' as const } : r))
}

describe('buildOptimizedPolicy', () => {
  it('narrows an Allow statement and keeps its Sid, Principal, and Condition', () => {
    const parsed = parsePolicy({
      Version: '2012-10-17',
      Statement: [{
        Sid: 'ReadReports',
        Effect: 'Allow',
        Principal: { AWS: 'arn:aws:iam::111122223333:root' },
        Action: ['s3:GetObject', 's3:PutObject'],
        Resource: ['arn:aws:s3:::example-bucket/*'],
        Condition: { Bool: { 'aws:SecureTransport': true } },
      }],
    })
    const rows = markNeeded(buildPermissionRows(parsed), r => r.action === 's3:GetObject')
    const out = buildOptimizedPolicy(parsed, rows)
    expect(out.Statement).toEqual([{
      Sid: 'ReadReports',
      Effect: 'Allow',
      Principal: { AWS: 'arn:aws:iam::111122223333:root' },
      Action: 's3:GetObject',
      Resource: 'arn:aws:s3:::example-bucket/*',
      Condition: { Bool: { 'aws:SecureTransport': true } },
    }])
  })

  it('keeps Deny statements exactly as written, even with nothing marked needed', () => {
    const deny = { Effect: 'Deny', Action: ['iam:CreateUser', 'iam:DeleteRole'], Resource: '*' }
    const parsed = parsePolicy({ Statement: [deny] })
    const rows = buildPermissionRows(parsed)
    expect(rows.every(r => r.locked)).toBe(true)
    expect(buildOptimizedPolicy(parsed, rows).Statement).toEqual([deny])
  })

  it('keeps NotAction and NotResource statements exactly as written', () => {
    const notAction = { Effect: 'Allow', NotAction: 'iam:*', Resource: '*' }
    const notResource = { Effect: 'Allow', Action: 's3:*', NotResource: 'arn:aws:s3:::example-bucket' }
    const parsed = parsePolicy({ Statement: [notAction, notResource] })
    const rows = buildPermissionRows(parsed)
    expect(rows.every(r => r.locked)).toBe(true)
    expect(rows[0].action).toBe('NotAction: iam:*')
    const out = buildOptimizedPolicy(parsed, rows)
    expect(out.Statement).toEqual([notAction, notResource])
    expect(out.Statement[0]).not.toHaveProperty('Action')
  })

  it('does not add a Resource to a trust policy statement', () => {
    const trust = {
      Effect: 'Allow',
      Principal: { Service: 'lambda.amazonaws.com' },
      Action: 'sts:AssumeRole',
    }
    const parsed = parsePolicy({ Version: '2012-10-17', Statement: [trust] })
    const out = buildOptimizedPolicy(parsed, buildPermissionRows(parsed))
    expect(out.Statement).toEqual([trust])
  })

  it('drops an Allow statement when none of its rows are needed', () => {
    const parsed = parsePolicy({
      Statement: [
        { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' },
        { Effect: 'Allow', Action: 'dynamodb:Query', Resource: 'arn:aws:dynamodb:us-east-1:111122223333:table/example-table' },
      ],
    })
    const rows = markNeeded(buildPermissionRows(parsed), r => r.action === 'dynamodb:Query')
    const out = buildOptimizedPolicy(parsed, rows)
    expect(out.Statement).toHaveLength(1)
    expect(out.Statement[0].Action).toBe('dynamodb:Query')
  })
})

describe('large policies', () => {
  // About 49,000 characters, under the input limit, but 9,000,000 action and
  // resource pairs. Building every pair used about 1 GB of memory.
  const n = 3000
  const big = parsePolicy({
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow',
      Action: Array.from({ length: n }, (_, i) => `s3:A${i}`),
      Resource: Array.from({ length: n }, (_, i) => `arn:aws:s3:::example-bucket-${i}`),
    }],
  })

  it('counts every row but builds only the rows the tables show', () => {
    const t0 = performance.now()
    const rows = buildPermissionRows(big)
    const summary = buildSummaryRows(big)
    // Generous bound: the point is the row cap, not speed. Building all
    // 9,000,000 rows took about 400 ms and 1 GB of memory.
    expect(performance.now() - t0).toBeLessThan(5000)
    expect(permissionRowCount(big)).toBe(n * n)
    expect(rows).toHaveLength(MAX_TABLE_ROWS)
    expect(summary.rows).toHaveLength(MAX_TABLE_ROWS)
    expect(summary.total).toBe(n * n)
  })

  it('keeps a statement with more rows than the table shows exactly as written', () => {
    const rows = buildPermissionRows(big)
    expect(rows[0].locked).toContain('9,000,000 action and resource pairs')
    const out = buildOptimizedPolicy(big, rows.map(r => ({ ...r, status: 'needed' as const })))
    expect(out.Statement).toEqual([big.statements[0].raw])
  })
})

describe('optimized policy Version', () => {
  const stmt = { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/${aws:username}/*' }
  const allNeeded = (p: ReturnType<typeof parsePolicy>) => buildOptimizedPolicy(p, markNeeded(buildPermissionRows(p), () => true))

  it('leaves Version out when the input had none, so ${...} stays plain text', () => {
    const p = parsePolicy({ Statement: [stmt] })
    const out = allNeeded(p)
    expect(out).not.toHaveProperty('Version')
    expect(Object.keys(out)).toEqual(['Statement'])
    expect(versionWarning(p)).toContain('no Version (treated as 2008-10-17)')
  })

  it('copies the Version exactly as written', () => {
    expect(allNeeded(parsePolicy({ Version: '2008-10-17', Statement: [stmt] })).Version).toBe('2008-10-17')
    expect(allNeeded(parsePolicy({ Version: '2012-10-17', Statement: [stmt] })).Version).toBe('2012-10-17')
  })

  it('warns only when the Version makes policy variables plain text', () => {
    expect(versionWarning(parsePolicy({ Version: '2008-10-17', Statement: [stmt] }))).toContain('Version 2008-10-17')
    expect(versionWarning(parsePolicy({ Version: '2012-10-17', Statement: [stmt] }))).toBeUndefined()
    expect(versionWarning(parsePolicy({ Statement: [{ ...stmt, Resource: 'arn:aws:s3:::example-bucket/*' }] }))).toBeUndefined()
  })
})
