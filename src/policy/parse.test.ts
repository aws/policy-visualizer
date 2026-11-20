// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { describeParseError, parsePolicy } from './parse'

describe('parsePolicy', () => {
  it('parses a multi-statement policy with Allow and Deny', () => {
    const parsed = parsePolicy({
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'S3ReadOnly',
          Effect: 'Allow',
          Action: ['s3:GetObject', 's3:ListBucket'],
          Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*'],
          Condition: { StringEquals: { 's3:prefix': 'reports/' } },
        },
        {
          Sid: 'BlockDangerous',
          Effect: 'Deny',
          Action: ['iam:CreateUser', 'iam:DeleteRole'],
          Resource: '*',
        },
      ],
    })

    expect(parsed.version).toBe('2012-10-17')
    expect(parsed.statements).toHaveLength(2)

    const [allow, deny] = parsed.statements
    expect(allow.effect).toBe('Allow')
    expect(allow.sid).toBe('S3ReadOnly')
    expect(allow.actions).toEqual(['s3:GetObject', 's3:ListBucket'])
    expect(allow.resources).toHaveLength(2)
    expect(allow.conditions).toEqual([
      { operator: 'StringEquals', key: 's3:prefix', values: ['reports/'] },
    ])

    expect(deny.effect).toBe('Deny')
    expect(deny.resources).toEqual(['*'])
    expect(deny.conditions).toEqual([])
  })

  it('normalizes a single statement object into an array', () => {
    const parsed = parsePolicy({
      Statement: { Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
    })
    expect(parsed.statements).toHaveLength(1)
    expect(parsed.statements[0].actions).toEqual(['s3:GetObject'])
  })

  it('falls back to NotAction and NotResource when Action/Resource are absent', () => {
    const parsed = parsePolicy({
      Statement: [{ Effect: 'Deny', NotAction: 'iam:*', NotResource: 'arn:aws:iam::*' }],
    })
    expect(parsed.statements[0].actions).toEqual(['iam:*'])
    expect(parsed.statements[0].resources).toEqual(['arn:aws:iam::*'])
  })

  it('parses principals from an object map', () => {
    const parsed = parsePolicy({
      Statement: [
        {
          Effect: 'Allow',
          Action: 'sts:AssumeRole',
          Principal: { AWS: 'arn:aws:iam::111122223333:root' },
        },
      ],
    })
    expect(parsed.statements[0].principals).toEqual([
      'AWS:arn:aws:iam::111122223333:root',
    ])
  })

  it('rejects a Condition whose operator does not map to key/value pairs', () => {
    expect(() =>
      parsePolicy({
        Statement: [
          { Effect: 'Allow', Action: 's3:GetObject', Condition: { StringEquals: 'not-a-map' } },
        ],
      })
    ).toThrow()
  })

  it('rejects input with an invalid Effect', () => {
    expect(() =>
      parsePolicy({ Statement: [{ Effect: 'Maybe', Action: 's3:GetObject' }] })
    ).toThrow()
  })

  it('accepts boolean and number condition values', () => {
    const parsed = parsePolicy({
      Statement: [{
        Effect: 'Deny',
        Action: 's3:*',
        Resource: '*',
        Condition: {
          Bool: { 'aws:SecureTransport': false },
          NumericLessThan: { 's3:TlsVersion': [1.2] },
        },
      }],
    })
    expect(parsed.statements[0].conditions).toEqual([
      { operator: 'Bool', key: 'aws:SecureTransport', values: ['false'] },
      { operator: 'NumericLessThan', key: 's3:TlsVersion', values: ['1.2'] },
    ])
  })

  it('flags NotAction, NotResource, and NotPrincipal and keeps the raw statement', () => {
    const stmt = {
      Effect: 'Deny',
      NotPrincipal: { AWS: 'arn:aws:iam::111122223333:root' },
      NotAction: 'iam:*',
      NotResource: 'arn:aws:s3:::example-bucket',
    }
    const [st] = parsePolicy({ Statement: [stmt] }).statements
    expect(st.notAction).toBe(true)
    expect(st.notResource).toBe(true)
    expect(st.notPrincipal).toBe(true)
    expect(st.raw).toEqual(stmt)

    const [plain] = parsePolicy({ Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*' }] }).statements
    expect([plain.notAction, plain.notResource, plain.notPrincipal]).toEqual([false, false, false])
  })
})

describe('describeParseError', () => {
  it('reports invalid JSON', () => {
    let err: unknown
    try { JSON.parse('{ not json') } catch (e) { err = e }
    expect(describeParseError(err)).toMatch(/^Invalid JSON: /)
  })

  it('reports the path of the first schema problem', () => {
    let err: unknown
    try { parsePolicy({ Statement: [{ Effect: 'Allow' }, { Effect: 'Maybe' }] }) } catch (e) { err = e }
    const msg = describeParseError(err)
    expect(msg).toMatch(/^Not a valid IAM policy: Statement/)
    expect(msg).not.toContain('{')
  })
})
