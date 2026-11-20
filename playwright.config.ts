// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from '@playwright/test'

// End-to-end browser tests. They build the app and serve the production build
// (with its Content-Security-Policy) on localhost, then drive it in Chromium.
//
// Environment variables:
// - E2E_BASE: base path to build and serve under, e.g. "/policy-visualizer/"
//   to mimic GitHub Pages. Defaults to the root.
// - PW_CHANNEL: browser channel, e.g. "chrome" to use an installed Google
//   Chrome instead of Playwright's bundled Chromium.
const PORT = 4173
const BASE = process.env.E2E_BASE ?? '/'

export default defineConfig({
  testDir: 'e2e',
  outputDir: 'e2e/.output',
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: `http://127.0.0.1:${PORT}${BASE}`,
    viewport: { width: 1600, height: 1000 },
    acceptDownloads: true,
    channel: process.env.PW_CHANNEL || undefined,
  },
  webServer: {
    command: `npm run build && npx vite preview --host 127.0.0.1 --port ${PORT} --strictPort`,
    url: `http://127.0.0.1:${PORT}${BASE}`,
    env: process.env.E2E_BASE ? { VITE_BASE: BASE } : {},
    reuseExistingServer: false,
    timeout: 180_000,
  },
})
