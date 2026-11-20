// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { getServicePrefix, serviceColor } from './serviceIcons'

describe('getServicePrefix', () => {
  it('detects the prefix of an action', () => {
    expect(getServicePrefix('s3:GetObject')).toBe('s3')
    expect(getServicePrefix('DynamoDB:Query')).toBe('dynamodb')
    expect(getServicePrefix('execute-api:Invoke')).toBe('execute-api')
  })

  it('detects the service of an ARN', () => {
    expect(getServicePrefix('arn:aws:s3:::example-bucket')).toBe('s3')
    expect(getServicePrefix('arn:aws:dynamodb:us-east-1:111122223333:table/example-table')).toBe('dynamodb')
    // Other partitions
    expect(getServicePrefix('arn:aws-cn:s3:::example-bucket')).toBe('s3')
    expect(getServicePrefix('arn:aws-us-gov:iam::111122223333:role/example-role')).toBe('iam')
  })

  it('returns null when there is no service', () => {
    expect(getServicePrefix('*')).toBeNull()
    expect(getServicePrefix('')).toBeNull()
    expect(getServicePrefix('StringEquals s3:prefix')).toBeNull()
  })
})

describe('serviceColor', () => {
  it('is deterministic per service', () => {
    expect(serviceColor('s3')).toBe(serviceColor('s3'))
    expect(serviceColor('s3')).not.toBe(serviceColor('iam'))
  })
})
