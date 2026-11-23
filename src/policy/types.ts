// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export type ConditionValue = string | number | boolean
export type PolicyDocument = {
  Version?: string
  Id?: string
  Statement: Statement | Statement[]
}
export type Statement = {
  Sid?: string
  Effect: 'Allow' | 'Deny'
  Action?: string | string[]
  NotAction?: string | string[]
  Resource?: string | string[]
  NotResource?: string | string[]
  Condition?: Record<string, Record<string, ConditionValue | ConditionValue[]>>
  Principal?: string | string[] | Record<string, string | string[]>
  NotPrincipal?: string | string[] | Record<string, string | string[]>
  [element: string]: unknown
}
export type ParsedPolicy = {
  id: string
  version: string | undefined
  policyId?: string
  unknownElements: { statement?: number; key: string; suggestion?: string }[]
  statements: ParsedStatement[]
  // Compact JSON length: white space between elements isn't counted, inside values it is.
  charCount: number
  sourcePath?: string
  sourceKeys?: (string | number)[]
  sourceCount?: number
}
export type ParsedStatement = {
  id: string
  sid?: string
  effect: 'Allow' | 'Deny'
  actions: string[]
  resources: string[]
  conditions: { operator: string; key: string; values: string[] }[]
  principals: string[]
  // From a Not* element, meaning "everything except these".
  notAction: boolean
  notResource: boolean
  notPrincipal: boolean
  // As it appeared in the input, so it can be written back unchanged.
  raw: Statement
}
