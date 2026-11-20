// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { safePixelRatio } from './exportSize'

describe('safePixelRatio', () => {
  it('uses the preferred ratio for normal diagrams', () => {
    expect(safePixelRatio(1128, 1376)).toBe(2)
  })

  it('lowers the ratio so a tall diagram stays within 16,384 px per side', () => {
    const height = 20000
    const ratio = safePixelRatio(1128, height)
    expect(height * ratio).toBeLessThanOrEqual(16384)
  })

  it('keeps the total canvas area within the browser limit', () => {
    const ratio = safePixelRatio(5000, 5000)
    expect(5000 * ratio * 5000 * ratio).toBeLessThanOrEqual(16_777_216 + 1)
  })
})
