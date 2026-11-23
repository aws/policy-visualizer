// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Safari caps canvas size at 16,384 px per side and 16,777,216 px in total, so large diagrams
// render at a lower pixel ratio.
const MAX_CANVAS_SIDE = 16384
const MAX_CANVAS_AREA = 16_777_216

export function safePixelRatio(width: number, height: number, preferred = 2): number {
  if (width <= 0 || height <= 0) return preferred
  return Math.min(
    preferred,
    MAX_CANVAS_SIDE / width,
    MAX_CANVAS_SIDE / height,
    Math.sqrt(MAX_CANVAS_AREA / (width * height))
  )
}
