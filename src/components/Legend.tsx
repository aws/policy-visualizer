// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import ServiceBadge from './ServiceBadge'

export default function Legend() {
  return (
    <div style={{ background: '#1a202c', borderRadius: '8px', overflow: 'hidden', marginBottom: '16px' }}>
      <div style={{ background: '#2d3748', padding: '12px 16px', borderBottom: '1px solid #4a5568' }}>
        <h3 style={{ margin: '0', color: '#fff', fontSize: '16px' }}>Legend</h3>
      </div>
      <div style={{ padding: '16px' }}>
        <div className="legend">
          <span className="badge"><span className="dot allow"></span>Allow</span>
          <span className="badge"><span className="dot deny"></span>Deny</span>
          <span className="badge"><span className="dot action"></span>Action</span>
          <span className="badge"><span className="dot resource"></span>Resource</span>
          <span className="badge"><span className="dot condition"></span>Condition</span>
        </div>
        <div style={{ marginTop: '12px', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '13px', color: '#9aa7c3' }}>Service:</span>
          <ServiceBadge prefix="s3" />
          <ServiceBadge prefix="iam" />
          <ServiceBadge prefix="dynamodb" />
        </div>
      </div>
    </div>
  )
}
