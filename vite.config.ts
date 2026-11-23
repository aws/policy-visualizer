// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// <reference types="vitest/config" />
import { defineConfig, type Plugin } from "vite";
import { configDefaults } from "vitest/config";
import react from "@vitejs/plugin-react";

// Restrictive Content-Security-Policy for static hosting. Injected only into
// production builds: the Vite dev server needs an inline script for React
// Fast Refresh, which a strict script-src would block.
// - style-src 'unsafe-inline': the app styles everything with inline styles.
// - img-src data: blob:: the favicon and html-to-image's PNG/PDF export
//   pipeline use data:/blob: URLs.
// - connect-src 'self': the bundled sample policy is fetched same-origin.
// frame-ancestors cannot be set via a <meta> tag; set it (or a full CSP
// header) at the web server or CDN if you need clickjacking protection.
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");

function injectCsp(): Plugin {
  return {
    name: "inject-csp-meta",
    apply: "build",
    transformIndexHtml() {
      return [
        {
          tag: "meta",
          attrs: { "http-equiv": "Content-Security-Policy", content: CSP },
          injectTo: "head-prepend",
        },
      ];
    },
  };
}

// Base path is configurable so the app can run from the root ("/"), a
// subfolder, or GitHub Pages. Set VITE_BASE at build time to override.
// Default "./" produces relative asset paths that work from any location.
export default defineConfig({
  plugins: [react(), injectCsp()],
  base: process.env.VITE_BASE ?? "./",
  server: {
    port: 3000,
  },
  build: {
    outDir: "dist",
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./tests/setup.ts"],
    globals: true,
    // Browser tests in e2e/ run under Playwright (npm run test:e2e), not vitest.
    exclude: [...configDefaults.exclude, "e2e/**"],
  },
});
