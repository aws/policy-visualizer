// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// IAM condition values may be strings, numbers, or booleans (or lists of them).
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
  // Elements outside IAM's grammar are kept so they can be reported.
  [element: string]: unknown
}
export type ParsedPolicy = {
  id: string
  version: string | undefined
  // The policy's optional Id element.
  policyId?: string
  // Keys that are not IAM policy elements, such as a misspelled "Actions".
  unknownElements: { statement?: number; key: string; suggestion?: string }[]
  statements: ParsedStatement[]
  // Policy length in characters as compact JSON: white space between
  // elements is not counted, white space inside values is.
  charCount: number
  // Where the policy was found in the pasted input (see findPolicy), and how
  // many policy documents the input held. Unset for a bare policy.
  sourcePath?: string
  // The same location as exact keys and array indexes (see FoundPolicy.keys).
  sourceKeys?: (string | number)[]
  sourceCount?: number
}
export type ParsedStatement = {
  id: string
  sid?: string
  effect: 'Allow' | 'Deny'
  // Values from Action or NotAction (see notAction), Resource or NotResource
  // (see notResource), and Principal or NotPrincipal (see notPrincipal).
  actions: string[]
  resources: string[]
  conditions: { operator: string; key: string; values: string[] }[]
  principals: string[]
  // True when the values came from the inverted "Not" element, which means
  // "everything except these".
  notAction: boolean
  notResource: boolean
  notPrincipal: boolean
  // The statement exactly as it appeared in the input, used to write it back
  // out unchanged.
  raw: Statement
}
