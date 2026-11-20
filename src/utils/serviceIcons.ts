// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Service identification without icon assets.
//
// Previously this module mapped services to AWS-owned icon files. It now
// returns the service prefix (for example "s3", "iam", "dynamodb") so the UI
// can render a styled text badge instead of a proprietary icon image.

// Detect the AWS service prefix from an IAM action (e.g. "s3:GetObject")
// or an ARN (e.g. "arn:aws:s3:::bucket"). Returns the lowercase prefix,
// or null when none can be determined (e.g. a bare "*").
export function getServicePrefix(actionOrArn: string): string | null {
  if (!actionOrArn) return null

  // ARN form, any partition (aws, aws-cn, aws-us-gov, ...):
  // arn:<partition>:<service>:<region>:<account>:<resource>
  if (actionOrArn.startsWith('arn:')) {
    return validPrefix(actionOrArn.split(':')[2])
  }

  // Action form: <service>:<Operation>
  const parts = actionOrArn.split(':')
  if (parts.length > 1) {
    return validPrefix(parts[0])
  }

  return null
}

// Service prefixes are lowercase letters, digits, and hyphens
// (e.g. "s3", "execute-api"). Anything else, such as "StringEquals s3",
// is not a service and gets no badge.
function validPrefix(candidate?: string): string | null {
  if (!candidate) return null
  const svc = candidate.toLowerCase()
  return /^[a-z0-9-]+$/.test(svc) ? svc : null
}

// Deterministic color for a service prefix, derived from a simple string
// hash so the same service always renders the same badge color.
export function serviceColor(prefix: string): string {
  let hash = 0
  for (let i = 0; i < prefix.length; i++) {
    hash = (hash << 5) - hash + prefix.charCodeAt(i)
    hash |= 0 // keep within 32-bit range
  }
  const hue = Math.abs(hash) % 360
  return `hsl(${hue}, 60%, 42%)`
}
