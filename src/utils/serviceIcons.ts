// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export function getServicePrefix(actionOrArn: string): string | null {
  if (!actionOrArn) return null

  // arn:<partition>:<service>:<region>:<account>:<resource>
  if (actionOrArn.startsWith('arn:')) {
    return validPrefix(actionOrArn.split(':')[2])
  }

  const parts = actionOrArn.split(':')
  if (parts.length > 1) {
    return validPrefix(parts[0])
  }

  return null
}

function validPrefix(candidate?: string): string | null {
  if (!candidate) return null
  const svc = candidate.toLowerCase()
  return /^[a-z0-9-]+$/.test(svc) ? svc : null
}

export function serviceColor(prefix: string): string {
  let hash = 0
  for (let i = 0; i < prefix.length; i++) {
    hash = (hash << 5) - hash + prefix.charCodeAt(i)
    hash |= 0 // keep within 32-bit range
  }
  const hue = Math.abs(hash) % 360
  return `hsl(${hue}, 60%, 42%)`
}
