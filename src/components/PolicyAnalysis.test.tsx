// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import PolicyAnalysis from './PolicyAnalysis'
import { parsePolicy } from '../policy/parse'
import { loadPolicyText } from '../policy/input'
import { Redactor, redactPolicy } from '../policy/redact'

// Hostile markup placed in policy values by a pasted policy. It must render
// as literal text in the Human-readable tab, never as elements.
const PAYLOAD = '<img src=x onerror=alert(1)>'

function renderHumanReadable(policy: unknown) {
  const parsed = parsePolicy(policy)
  const view = render(<PolicyAnalysis parsed={parsed} />)
  // Expand the collapsed panel, then open the Human-readable tab.
  fireEvent.click(screen.getByText('Policy analysis'))
  fireEvent.click(screen.getByRole('button', { name: 'Human-readable' }))
  return view
}

describe('PolicyAnalysis Human-readable tab', () => {
  it('renders hostile markup in resources and conditions as text, not elements', () => {
    const { container } = renderHumanReadable({
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'XssProbe',
          Effect: 'Allow',
          Action: ['s3:GetObject'],
          Resource: [`arn:aws:s3:::example-bucket/${PAYLOAD}`],
          Condition: { StringEquals: { 's3:prefix': PAYLOAD } },
        },
      ],
    })

    // The payload text is visible to the user...
    expect(container.textContent).toContain(`example-bucket/${PAYLOAD}`)
    expect(container.textContent).toContain(`StringEquals s3:prefix: ${PAYLOAD}`)
    // ...but no <img> (or any markup from the payload) was created.
    expect(container.querySelector('img')).toBeNull()
  })

  it('renders hostile markup in action names as text, not elements', () => {
    const { container } = renderHumanReadable({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Action: [PAYLOAD],
          Resource: '*',
        },
      ],
    })

    expect(container.textContent).toContain(PAYLOAD)
    expect(container.querySelector('img')).toBeNull()
  })

  it('keeps the plain-English translation for normal policies', () => {
    const { container } = renderHumanReadable({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Action: ['s3:GetObject', 's3:List*', 'dynamodb:*'],
          Resource: ['arn:aws:s3:::example-bucket'],
        },
      ],
    })

    const text = container.textContent ?? ''
    expect(text).toMatch(/perform\s+get object in s3/)
    expect(text).toMatch(/any action\s+starting with List in s3/)
    expect(text).toMatch(/perform any action\s+in dynamodb/)
    expect(text).toContain('arn:aws:s3:::example-bucket')
  })

  it('describes NotAction and NotResource as "everything except"', () => {
    const { container } = renderHumanReadable({
      Version: '2012-10-17',
      Statement: [
        { Effect: 'Deny', NotAction: ['iam:*'], NotResource: 'arn:aws:s3:::example-bucket' },
      ],
    })
    const text = container.textContent ?? ''
    expect(text).toContain('is denied from performing every action except')
    expect(text).toContain('iam:*')
    expect(text).toContain('on every resource except')
    expect(text).not.toMatch(/perform any action\s+in iam/)
  })
})

describe('PolicyAnalysis with redaction', () => {
  function openTab(policy: unknown, tab: string, redact: boolean) {
    const parsed = parsePolicy(policy)
    const redactor = redact ? new Redactor() : null
    const view = render(<PolicyAnalysis parsed={parsed} displayParsed={redactor ? redactPolicy(parsed, redactor) : null} redactor={redactor} />)
    fireEvent.click(screen.getByText('Policy analysis'))
    fireEvent.click(screen.getByRole('button', { name: tab }))
    return view
  }
  const trust = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::444455556666:root' }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' }] }

  it('masks the Check access resource and caller fields while redacting', () => {
    openTab(trust, 'Check access', true)
    expect(screen.getByLabelText('Resource ARN (optional)')).toHaveAttribute('type', 'password')
    expect(screen.getByLabelText('Caller principal (optional)')).toHaveAttribute('type', 'password')
    // Saved passwords must not be filled into the masked fields.
    expect(screen.getByLabelText('Resource ARN (optional)')).toHaveAttribute('autocomplete', 'new-password')
    // Action names are not redacted anywhere, so the field stays readable.
    expect(screen.getByLabelText('Action')).not.toHaveAttribute('type', 'password')
  })

  it('leaves the Check access fields readable when not redacting', () => {
    openTab(trust, 'Check access', false)
    expect(screen.getByLabelText('Resource ARN (optional)')).toHaveAttribute('type', 'text')
  })
})

describe('PolicyAnalysis Optimize tab', () => {
  it('warns that a missing Version makes ${...} plain text, and counts rows it does not build', () => {
    render(<PolicyAnalysis parsed={parsePolicy({ Statement: [
      { Effect: 'Allow', Action: Array.from({ length: 50 }, (_, i) => `s3:A${i}`), Resource: Array.from({ length: 50 }, (_, i) => `arn:aws:s3:::example-bucket/\${aws:username}/${i}`) },
    ] })} />)
    fireEvent.click(screen.getByText('Policy analysis'))
    fireEvent.click(screen.getByRole('button', { name: 'Optimize' }))
    expect(screen.getByTestId('optimize-version-warning')).toHaveTextContent('no Version (treated as 2008-10-17)')
    expect(screen.getByText(/Showing the first 2,000 of 2,500 rows/)).toBeInTheDocument()
  })
})

describe('PolicyAnalysis guardrail notice', () => {
  const fullAccess = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }

  it('says grant checks are off for a type detected from the wrapper, and for a type the user picks', () => {
    render(<PolicyAnalysis parsed={loadPolicyText(JSON.stringify({ Policy: { Content: JSON.stringify(fullAccess) } }))} />)
    fireEvent.click(screen.getByText('Policy analysis'))
    expect(screen.getByTestId('guardrail-notice')).toHaveTextContent('detected as an SCP or RCP from the input wrapper (Policy.Content')
    expect(screen.getByTestId('guardrail-notice')).toHaveTextContent('Grant checks are off for this type')
    const select = screen.getByDisplayValue('Detected: SCP or RCP (Organizations)')
    fireEvent.change(select, { target: { value: 'boundary' } })
    expect(screen.getByTestId('guardrail-notice')).toHaveTextContent('The policy type is set to a permissions boundary.')
    expect(screen.getByTestId('guardrail-notice')).toHaveTextContent('If this is not really a permissions boundary, switch the policy type')
    fireEvent.change(select, { target: { value: 'identity' } })
    expect(screen.queryByTestId('guardrail-notice')).toBeNull()
    expect(screen.getByTestId('findings')).toHaveTextContent('Allows all actions')
  })

  it('shows no notice for other policy types', () => {
    render(<PolicyAnalysis parsed={parsePolicy(fullAccess)} />)
    fireEvent.click(screen.getByText('Policy analysis'))
    expect(screen.queryByTestId('guardrail-notice')).toBeNull()
  })
})
