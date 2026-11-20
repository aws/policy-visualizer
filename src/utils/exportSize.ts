// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Browsers cap canvas size. Safari is the strictest: 16,384 px per side and
// 16,777,216 px in total. Exports over the cap fail, so very large diagrams
// are rendered at a lower pixel ratio instead.
const MAX_CANVAS_SIDE = 16384
const MAX_CANVAS_AREA = 16_777_216

// Largest pixel ratio, up to `preferred`, that keeps a width x height export
// within canvas limits.
export function safePixelRatio(width: number, height: number, preferred = 2): number {
  if (width <= 0 || height <= 0) return preferred
  return Math.min(
    preferred,
    MAX_CANVAS_SIDE / width,
    MAX_CANVAS_SIDE / height,
    Math.sqrt(MAX_CANVAS_AREA / (width * height))
  )
}
