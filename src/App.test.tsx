// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import App from './App'

describe('App', () => {
  it('renders the toolbar heading', () => {
    render(<App />)
    expect(screen.getByText(/Policy Visualizer/i)).toBeInTheDocument()
  })

  it('shows the empty state before a policy is loaded', () => {
    render(<App />)
    expect(
      screen.getByText(/Load a policy to see the visualization/i)
    ).toBeInTheDocument()
  })

  it('renders the policy upload controls', () => {
    render(<App />)
    expect(screen.getByText('Load policy JSON')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Parse/i })).toBeInTheDocument()
  })
})
