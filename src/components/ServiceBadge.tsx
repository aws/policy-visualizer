// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { getServicePrefix, serviceColor } from '../utils/serviceIcons'

// Small rounded-rectangle text badge showing an AWS service prefix
// (e.g. "s3", "iam"). The background color is deterministic per service.
// This replaces the previous AWS service icon images, so no proprietary
// icon assets are bundled or redistributed.
export default function ServiceBadge({
  value,
  prefix,
}: {
  value?: string
  prefix?: string
}) {
  const svc = prefix ?? (value ? getServicePrefix(value) : null)
  if (!svc) return null

  return (
    <span
      title={svc}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '2px 6px',
        borderRadius: 6,
        background: serviceColor(svc),
        color: '#fff',
        fontSize: 11,
        fontWeight: 700,
        letterSpacing: 0.3,
        textTransform: 'uppercase',
        lineHeight: 1.4,
        flex: '0 0 auto',
        maxWidth: 88,
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
      }}
    >
      {svc}
    </span>
  )
}
