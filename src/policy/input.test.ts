// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { findPolicy, parseInputText } from './input'

// Wrapper shapes follow AWS CLI and CloudFormation output. Values are
// placeholders (account 111122223333, example names).
const POLICY = {
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' }],
}

describe('findPolicy', () => {
  it('returns a bare policy unchanged', () => {
    expect(findPolicy(POLICY)).toEqual({ policy: POLICY, path: '', keys: [], count: 1 })
  })

  it('unwraps get-bucket-policy output, where the policy is a JSON string', () => {
    const found = findPolicy({ Policy: JSON.stringify(POLICY) })
    expect(found?.policy).toEqual(POLICY)
    expect(found?.path).toBe('Policy (JSON string)')
  })

  it('unwraps get-policy-version and get-role output', () => {
    expect(findPolicy({ PolicyVersion: { Document: POLICY, VersionId: 'v1', IsDefaultVersion: true } })?.path)
      .toBe('PolicyVersion.Document')
    expect(findPolicy({ Role: { RoleName: 'example-role', AssumeRolePolicyDocument: POLICY } })?.path)
      .toBe('Role.AssumeRolePolicyDocument')
  })

  it('unwraps organizations describe-policy output', () => {
    const found = findPolicy({ Policy: { PolicySummary: { Name: 'example-scp' }, Content: JSON.stringify(POLICY) } })
    expect(found?.path).toBe('Policy.Content (JSON string)')
    expect(found?.policy).toEqual(POLICY)
  })

  it('finds every policy in a CloudFormation template and uses the first', () => {
    const found = findPolicy({
      Resources: {
        ExampleRole: { Type: 'AWS::IAM::Role', Properties: { AssumeRolePolicyDocument: POLICY } },
        ExamplePolicy: { Type: 'AWS::IAM::ManagedPolicy', Properties: { PolicyDocument: POLICY } },
      },
    })
    expect(found?.count).toBe(2)
    expect(found?.path).toBe('Resources.ExampleRole.Properties.AssumeRolePolicyDocument')
  })

  it('returns null when there is no policy', () => {
    expect(findPolicy({ Hello: 'world' })).toBeNull()
  })
})

describe('parseInputText', () => {
  it('decodes URL-encoded policy documents', () => {
    expect(parseInputText(encodeURIComponent(JSON.stringify(POLICY)))).toEqual(POLICY)
  })

  it('keeps "+" and "%3A" in ordinary policies untouched', () => {
    const p = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*',
      Condition: { StringEquals: { 'aws:PrincipalTag/token': 'a+b%3Ac' } } }] }
    expect(parseInputText(JSON.stringify(p))).toEqual(p)
    // An encoded document still decodes, and its "+" stays a plus.
    expect(parseInputText(encodeURIComponent(JSON.stringify(p)))).toEqual(p)
  })

  it('throws SyntaxError on invalid JSON', () => {
    expect(() => parseInputText('{ nope')).toThrow(SyntaxError)
  })
})
