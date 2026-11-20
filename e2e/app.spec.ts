// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { test as base, expect, type Page } from '@playwright/test'
import fs from 'node:fs'

// Browser tests against the production build. Every test also checks that
// the page made no requests outside its own origin, had no failed requests,
// and logged no errors: the app must run fully in the browser.
//
// Fixtures use AWS documentation placeholders only (account 111122223333,
// example resource names).

const test = base.extend<{ guard: void }>({
  guard: [async ({ page, baseURL }, use) => {
    const host = new URL(baseURL ?? 'http://127.0.0.1').host
    const external: string[] = []
    const failed: string[] = []
    const errors: string[] = []
    page.on('request', r => {
      const u = r.url()
      if (u.startsWith('data:') || u.startsWith('blob:')) return
      if (new URL(u).host !== host) external.push(u)
    })
    page.on('response', r => { if (r.status() >= 400) failed.push(`${r.status()} ${r.url()}`) })
    page.on('console', m => { if (m.type() === 'error') errors.push(`${m.text()} [${m.location().url}]`) })
    page.on('pageerror', e => errors.push(String(e)))
    await use()
    expect(external, 'requests outside the app origin').toEqual([])
    expect(failed, 'failed requests').toEqual([])
    expect(errors, 'console or page errors').toEqual([])
  }, { auto: true }],
})

const graphNodes = (page: Page) => page.locator('.graph-container foreignObject')
const optimizeRows = (page: Page) => page.locator('table:has(th:text("Status")) tbody tr')

async function loadSample(page: Page) {
  await page.goto('./')
  await expect(page.getByText('Load a policy to see the visualization')).toBeVisible()
  await page.getByRole('button', { name: 'Load Sample Policy' }).click()
  await expect(page.getByText('Statement 1: Allow')).toBeVisible()
}

async function pastePolicy(page: Page, policy: unknown) {
  await page.goto('./')
  await page.locator('textarea').fill(JSON.stringify(policy))
  await page.getByRole('button', { name: 'Parse', exact: true }).click()
}

// Count diagram nodes that fall outside the visible graph container, in
// total and horizontally only.
async function nodesOutsideView(page: Page) {
  return page.evaluate(() => {
    const c = (document.querySelector('.graph-container') as HTMLElement).getBoundingClientRect()
    const nodes = [...document.querySelectorAll('.graph-container foreignObject')].map(n => n.getBoundingClientRect())
    const outside = nodes.filter(r => r.left < c.left - 1 || r.right > c.right + 1 || r.top < c.top - 1 || r.bottom > c.bottom + 1).length
    const outsideHorizontally = nodes.filter(r => r.left < c.left - 1 || r.right > c.right + 1).length
    return { total: nodes.length, outside, outsideHorizontally }
  })
}

// Diagram nodes that overlap the zoom controls.
async function nodesUnderControls(page: Page) {
  return page.evaluate(() => {
    const ctl = (document.querySelector('[data-testid="zoom-controls"]') as HTMLElement).getBoundingClientRect()
    return [...document.querySelectorAll('.graph-container foreignObject')]
      .map(n => n.getBoundingClientRect())
      .filter(r => r.left < ctl.right && r.right > ctl.left && r.top < ctl.bottom && r.bottom > ctl.top).length
  })
}

function viewZoom(page: Page) {
  return viewTransform(page).then(t => Number(/scale\(([\d.]+)\)/.exec(t ?? '')?.[1]))
}

// On-screen size of diagram item text, in CSS pixels after zoom.
async function itemTextPx(page: Page) {
  const zoom = await viewZoom(page)
  const css = await page.locator('.graph-container foreignObject', { hasText: 's3:GetObject' }).first()
    .getByText('s3:GetObject', { exact: true }).evaluate(e => parseFloat(getComputedStyle(e).fontSize))
  return css * zoom
}

function viewTransform(page: Page) {
  return page.locator('.graph-container svg > g').first().getAttribute('transform')
}

async function openAnalysisTab(page: Page, tab: 'Overview' | 'Human Readable' | 'Optimize' | 'Compare' | 'Check access') {
  await page.locator('h3', { hasText: 'Policy Analysis' }).first().click()
  await page.getByRole('button', { name: tab, exact: true }).click()
}

test('loads the sample policy and renders the diagram', async ({ page }) => {
  await loadSample(page)
  // 1 policy + 3 statements + 12 items
  await expect(graphNodes(page)).toHaveCount(16)
  expect(await nodesOutsideView(page)).toEqual({ total: 16, outside: 0, outsideHorizontally: 0 })
  expect(await nodesUnderControls(page)).toBe(0)
  expect(await itemTextPx(page)).toBeGreaterThanOrEqual(11)
  await expect(page.locator('.graph-container img')).toHaveCount(0)
})

test('shows service badges with one color per service, and none on conditions', async ({ page }) => {
  await loadSample(page)
  for (const svc of ['s3', 'dynamodb', 'iam']) {
    expect(await page.locator(`.graph-container span[title="${svc}"]`).count()).toBeGreaterThan(0)
  }
  const s3Colors = await page.locator('.graph-container span[title="s3"]')
    .evaluateAll(els => [...new Set(els.map(e => getComputedStyle(e).backgroundColor))])
  expect(s3Colors).toHaveLength(1)
  await expect(page.locator('.graph-container foreignObject:has-text("Condition") span[title]')).toHaveCount(0)
})

test('collapsing and expanding a statement keeps the current view', async ({ page }) => {
  await loadSample(page)
  const before = await viewTransform(page)
  await page.getByText('Statement 1: Allow').click()
  await expect(graphNodes(page)).toHaveCount(11)
  await page.getByText('Statement 1: Allow').click()
  await expect(graphNodes(page)).toHaveCount(16)
  expect(await viewTransform(page)).toBe(before)
})

test('dragging that starts and ends on a statement node pans instead of collapsing it', async ({ page }) => {
  await loadSample(page)
  const node = page.getByText('Statement 1: Allow')
  const box = await node.boundingBox()
  if (!box) throw new Error('statement node not found')
  const before = await viewTransform(page)
  await page.mouse.move(box.x + 20, box.y + 10)
  await page.mouse.down()
  await page.mouse.move(box.x + 60, box.y + 12, { steps: 5 })
  await page.mouse.move(box.x + 22, box.y + 10, { steps: 5 })
  await page.mouse.up()
  await expect(graphNodes(page)).toHaveCount(16)
  expect(await viewTransform(page)).not.toBe(before)
  // A plain click still toggles it.
  await node.click()
  await expect(graphNodes(page)).toHaveCount(11)
})

test('choosing the same file twice loads it both times', async ({ page }, testInfo) => {
  const file = testInfo.outputPath('policy.json')
  fs.writeFileSync(file, JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' }] }))
  await page.goto('./')
  const input = page.locator('input[type="file"]')
  await input.setInputFiles(file)
  await expect(page.getByText('Statement 1: Allow')).toBeVisible()
  await page.getByRole('button', { name: 'Clear', exact: true }).click()
  await expect(page.getByText('Load a policy to see the visualization')).toBeVisible()
  await input.setInputFiles(file)
  await expect(page.getByText('Statement 1: Allow')).toBeVisible()
})

test('scroll pans the diagram and Ctrl + scroll zooms', async ({ page }) => {
  await loadSample(page)
  const start = await viewTransform(page)
  const zoom = await viewZoom(page)
  await page.mouse.move(1100, 500)
  await page.mouse.wheel(0, 300)
  await expect.poll(() => viewTransform(page)).not.toBe(start)
  expect(await viewZoom(page)).toBe(zoom)
  await page.keyboard.down('Control')
  await page.mouse.wheel(0, -200)
  await page.keyboard.up('Control')
  await expect.poll(() => viewZoom(page)).toBeGreaterThan(zoom)
  // The browser's own page zoom is blocked: the wheel event is cancelled.
  const prevented = await page.locator('.graph-container').evaluate(el => {
    const ev = new WheelEvent('wheel', { deltaY: -100, ctrlKey: true, bubbles: true, cancelable: true })
    el.dispatchEvent(ev)
    return ev.defaultPrevented
  })
  expect(prevented).toBe(true)
})

test('analysis panel tabs and summary table', async ({ page }) => {
  await loadSample(page)
  await openAnalysisTab(page, 'Overview')
  await expect(page.getByText('Wildcard Actions')).toBeVisible()

  await page.getByRole('button', { name: 'Human Readable' }).click()
  await expect(page.getByText('Human Readable Translation')).toBeVisible()
  const body = await page.locator('body').innerText()
  expect(body).toMatch(/perform get object in s3/i)
  expect(body).toMatch(/is denied from/i)

  await page.getByRole('button', { name: 'Optimize' }).click()
  await expect(optimizeRows(page)).toHaveCount(9)

  await page.locator('h3', { hasText: 'Policy Summary' }).click()
  await expect(page.locator('table:has(th:text("Stmt")) tbody tr')).toHaveCount(9)
})

test('optimized policy keeps conditions and never trims Deny statements', async ({ page }) => {
  await loadSample(page)
  await openAnalysisTab(page, 'Optimize')
  await expect(optimizeRows(page).filter({ hasText: 'Kept as written' })).toHaveCount(2)

  // Mark only s3:GetObject on example-bucket as needed.
  await optimizeRows(page).first().locator('select').selectOption('needed')
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Download Optimized Policy' }).click(),
  ])
  const policy = JSON.parse(fs.readFileSync(await download.path(), 'utf8'))
  expect(policy.Statement).toEqual([
    {
      Sid: 'S3ReadOnly',
      Effect: 'Allow',
      Action: 's3:GetObject',
      Resource: 'arn:aws:s3:::example-bucket',
      Condition: { StringEquals: { 's3:prefix': 'reports/' } },
    },
    {
      Sid: 'BlockDangerous',
      Effect: 'Deny',
      Action: ['iam:CreateUser', 'iam:DeleteRole'],
      Resource: '*',
    },
  ])
})

test('NotAction statements are described as "everything except" and cannot be trimmed', async ({ page }) => {
  await pastePolicy(page, {
    Version: '2012-10-17',
    Statement: [{ Sid: 'AllExceptIam', Effect: 'Allow', NotAction: 'iam:*', Resource: '*' }],
  })
  await expect(page.getByText('NotAction', { exact: true })).toBeVisible()
  await openAnalysisTab(page, 'Human Readable')
  await expect(page.getByText(/is allowed to perform every action except/)).toBeVisible()
  await page.getByRole('button', { name: 'Optimize' }).click()
  await expect(optimizeRows(page).filter({ hasText: 'Kept as written' })).toHaveCount(1)
})

test('sample policy has no findings, and Optimize shows a review warning', async ({ page }) => {
  await loadSample(page)
  await openAnalysisTab(page, 'Overview')
  await expect(page.getByText('No issues found by the offline checks.')).toBeVisible()
  await expect(page.getByText(/^Size: [\d,]+ of 6,144 characters/)).toBeVisible()
  await page.getByRole('button', { name: 'Optimize' }).click()
  await expect(page.getByRole('note').filter({ hasText: 'Review before use.' })).toBeVisible()
})

test('flags public access and cross-account principals', async ({ page }) => {
  // 111122223333 is "your" account; 444455556666 is another account.
  await pastePolicy(page, {
    Version: '2012-10-17',
    Statement: [
      { Sid: 'PublicRead', Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' },
      { Sid: 'PartnerList', Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::444455556666:root' }, Action: 's3:ListBucket', Resource: 'arn:aws:s3:::example-bucket' },
    ],
  })
  await openAnalysisTab(page, 'Overview')
  const findings = page.getByTestId('findings')
  await expect(findings.locator('li[data-severity="high"]', { hasText: 'Public access' })).toBeVisible()
  await expect(findings.getByText(/Enter your account ID to flag cross-account access/)).toBeVisible()

  await page.getByPlaceholder('12-digit account ID').fill('111122223333')
  await expect(findings.locator('li[data-severity="medium"]', { hasText: 'Cross-account access' })).toContainText('444455556666')

  await page.getByRole('button', { name: 'Human Readable' }).click()
  await expect(page.getByText(/Anyone \(public access\)\s+is allowed to/)).toBeVisible()
})

test('accepts AWS CLI output and reports where the policy was found', async ({ page }) => {
  // Shape of `aws s3api get-bucket-policy` output: the policy is a JSON string.
  const bucketPolicy = {
    Version: '2012-10-17',
    Statement: [{ Sid: 'PublicRead', Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' }],
  }
  await pastePolicy(page, { Policy: JSON.stringify(bucketPolicy) })
  await expect(page.getByText('Statement 1: Allow')).toBeVisible()
  await expect(page.getByTestId('policy-source')).toContainText('Policy (JSON string)')
  await openAnalysisTab(page, 'Overview')
  await expect(page.locator('select').filter({ hasText: 'Detected: Resource-based policy' })).toBeVisible()
})

test('SCPs are detected from describe-policy output and do not flag FullAWSAccess', async ({ page }) => {
  const fullAccess = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }
  await pastePolicy(page, { Policy: { PolicySummary: { Name: 'FullAWSAccess' }, Content: JSON.stringify(fullAccess) } })
  await openAnalysisTab(page, 'Overview')
  await expect(page.locator('select').filter({ hasText: 'Detected: SCP or RCP (Organizations)' })).toBeVisible()
  await expect(page.getByText('No issues found by the offline checks.')).toBeVisible()
  await expect(page.getByTestId('guardrail-notice')).toContainText('detected as an SCP or RCP from the input wrapper')
  await expect(page.getByTestId('guardrail-notice')).toContainText('Grant checks are off for this type')
  // The same policy as an identity policy grants everything.
  await page.locator('select').filter({ hasText: 'Detected:' }).selectOption('identity')
  await expect(page.getByTestId('guardrail-notice')).toHaveCount(0)
  await expect(page.getByTestId('findings').locator('li[data-severity="high"]', { hasText: 'Allows all actions' })).toBeVisible()
})

test('flags condition operator pitfalls', async ({ page }) => {
  await pastePolicy(page, {
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow', Action: 's3:PutObject', Resource: 'arn:aws:s3:::example-bucket/*',
      Condition: { 'ForAllValues:StringEquals': { 'aws:TagKeys': ['Project'] }, StringEquals: { 's3:prefix': 'home/*' } },
    }],
  })
  await openAnalysisTab(page, 'Overview')
  const findings = page.getByTestId('findings')
  await expect(findings.getByText('ForAllValues passes when the key is missing')).toBeVisible()
  await expect(findings.getByText('Wildcard in an exact-match condition')).toBeVisible()
})

test('redacting the diagram hides identifiers and still exports', async ({ page }) => {
  await pastePolicy(page, {
    Version: '2012-10-17',
    Statement: [
      { Sid: 'ExampleCorpPartner', Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::444455556666:root' }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' },
      { Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::111122223333:root' }, Action: 'dynamodb:Query', Resource: 'arn:aws:dynamodb:us-east-1:111122223333:table/example-table' },
    ],
  })
  const diagram = page.locator('.graph-container')
  await expect(diagram).toContainText('example-bucket')
  await page.getByLabel('Redact names and IDs').check()
  await expect(diagram).toContainText('ACCOUNT-1')
  const text = await diagram.evaluate(el => el.textContent + ' ' + [...el.querySelectorAll('[title]')].map(e => e.getAttribute('title')).join(' '))
  for (const secret of ['444455556666', '111122223333', 'example-bucket', 'example-table', 'ExampleCorpPartner']) {
    expect(text).not.toContain(secret)
  }
  const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export PNG' }).click()])
  expect(fs.statSync(await download.path()).size).toBeGreaterThan(10_000)
})

test('redaction covers the whole page, not only the diagram', async ({ page }) => {
  const before = { Version: '2012-10-17', Statement: [
    { Sid: 'AcmePartnerRead', Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::444455556666:root' }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::acme-reports/*' }] }
  const after = { Version: '2012-10-17', Statement: [
    { Sid: 'AcmePartnerRead', Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::444455556666:root' }, Action: ['s3:GetObject', 's3:PutObject'], Resource: 'arn:aws:s3:::acme-reports/*',
      Condition: { StringEquals: { 'aws:SourceVpce': 'vpce-acme01' } } }] }
  await pastePolicy(page, { Policy: JSON.stringify(after) })
  // Run a comparison before redacting, then open every panel.
  await openAnalysisTab(page, 'Compare')
  await page.getByLabel('Previous policy version').fill(JSON.stringify(before))
  await page.getByRole('button', { name: 'Show changes' }).click()
  await expect(page.getByTestId('policy-diff')).toBeVisible()
  await page.getByLabel('Redact names and IDs').check()

  await expect(page.getByTestId('policy-text-hidden')).toBeVisible()
  const secrets = ['444455556666', 'acme', 'Acme', 'vpce-acme01']
  const pageText = async () => page.evaluate(() => document.body.innerText + ' ' +
    [...document.querySelectorAll('[title]')].map(e => e.getAttribute('title')).join(' ') + ' ' +
    [...document.querySelectorAll('input, textarea')].map(e => (e as HTMLInputElement).type === 'password' ? '' : (e as HTMLInputElement).value).join(' '))
  const expectClean = async (where: string) => {
    const text = await pageText()
    for (const secret of secrets) expect(text, `${secret} visible in ${where}`).not.toContain(secret)
  }
  await expect(page.getByTestId('policy-diff')).toContainText('aws:SourceVpce: VALUE-1')
  await expectClean('Compare')
  for (const tab of ['Overview', 'Human Readable', 'Optimize'] as const) {
    await page.getByRole('button', { name: tab, exact: true }).click()
    await expectClean(tab)
  }
  // The Optimize download is the real policy, and the page says so.
  await page.getByRole('button', { name: 'Optimize', exact: true }).click()
  await expect(page.getByTestId('download-not-redacted')).toBeVisible()
  await page.getByRole('button', { name: 'Check access', exact: true }).click()
  await page.getByLabel('Action').fill('s3:PutObject')
  // Typed values are not redacted, so the field is masked instead.
  await page.getByLabel('Resource ARN (optional)').fill('arn:aws:s3:::acme-reports/q1.csv')
  await page.getByRole('button', { name: 'Check', exact: true }).click()
  await expect(page.getByTestId('access-result')).toBeVisible()
  await expectClean('Check access')
  await page.locator('h3', { hasText: 'Policy Summary' }).click()
  await expectClean('Policy Summary')

  // Turning redaction off restores the real values.
  await page.getByLabel('Redact names and IDs').uncheck()
  await expect(page.locator('textarea').first()).toHaveValue(/acme-reports/)
})

test('rejects input over the size limit with a clear message', async ({ page }) => {
  await page.goto('./')
  const resources = Array.from({ length: 4000 }, (_, i) => `arn:aws:s3:::example-bucket-${i}/*`)
  await page.locator('textarea').fill(JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: resources }] }))
  await page.getByRole('button', { name: 'Parse', exact: true }).click()
  await expect(page.getByText(/this tool supports up to 100,000/)).toBeVisible()
  await expect(page.getByText('Load a policy to see the visualization')).toBeVisible()
})

test('copied Markdown escapes values that could become links or HTML', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await pastePolicy(page, { Version: '2012-10-17', Statement: [
    { Sid: 'x](https://example.invalid/track)![y', Effect: 'Allow', NotAction: '<img src=https://example.invalid/p>', Resource: '*' }] })
  await openAnalysisTab(page, 'Overview')
  await page.getByRole('button', { name: 'Copy as Markdown' }).click()
  await expect(page.getByRole('status')).toHaveText('Copied.')
  const md = await page.evaluate(() => navigator.clipboard.readText())
  // Policy values are inside code spans, which render as plain text.
  expect(md).toContain('`Allows every action except <img src=https://example.invalid/p>, including actions added to AWS in the future.`')
  expect(md).toContain('1 \\(`x](https://example.invalid/track)![y`\\)')
  const outsideCode = md.replace(/(`+)(?!`)[\s\S]*?(?<!`)\1(?!`)/g, '')
  expect(outsideCode).not.toContain('https://example.invalid')
})

test('copies findings as Markdown, redacted when redaction is on', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await pastePolicy(page, {
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::444455556666:root' }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' }],
  })
  await page.getByLabel('Redact names and IDs').check()
  await openAnalysisTab(page, 'Overview')
  await page.getByPlaceholder('12-digit account ID').fill('111122223333')
  await page.getByRole('button', { name: 'Copy as Markdown' }).click()
  await expect(page.getByRole('status')).toHaveText('Copied (redacted).')
  const md = await page.evaluate(() => navigator.clipboard.readText())
  expect(md).toContain('| Severity | Finding | Statement | Detail |')
  expect(md).toContain('Cross-account access')
  expect(md).toContain('ACCOUNT-')
  expect(md).not.toContain('444455556666')
})

test('compares with a previous version', async ({ page }) => {
  await pastePolicy(page, {
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: ['s3:GetObject', 's3:*'], Resource: 'arn:aws:s3:::example-bucket/*' }],
  })
  await openAnalysisTab(page, 'Compare')
  await page.getByLabel('Previous policy version').fill(JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' }],
  }))
  await page.getByRole('button', { name: 'Show changes' }).click()
  const diff = page.getByTestId('policy-diff')
  await expect(diff).toContainText('+ s3:*')
  await expect(diff).toContainText('Allows all actions in a service')
})

test('compare reports an action that moves to another statement', async ({ page }) => {
  const statements = (first: string[]) => ({ Version: '2012-10-17', Statement: [
    { Effect: 'Allow', Action: first, Resource: 'arn:aws:s3:::example-public/*' },
    { Effect: 'Allow', Action: 's3:DeleteObject', Resource: 'arn:aws:s3:::example-scratch/*' }] })
  await pastePolicy(page, statements(['s3:GetObject', 's3:DeleteObject']))
  await openAnalysisTab(page, 'Compare')
  await page.getByLabel('Previous policy version').fill(JSON.stringify(statements(['s3:GetObject'])))
  await page.getByRole('button', { name: 'Show changes' }).click()
  const diff = page.getByTestId('policy-diff')
  await expect(diff).toContainText('+ Allow; Action: s3:DeleteObject, s3:GetObject; Resource: arn:aws:s3:::example-public/*')
  await expect(diff).toContainText('- Allow; Action: s3:GetObject; Resource: arn:aws:s3:::example-public/*')
  await expect(page.getByText('No differences.')).toHaveCount(0)
})

test('checks whether the policy allows a request', async ({ page }) => {
  await loadSample(page)
  await openAnalysisTab(page, 'Check access')
  await expect(page.getByRole('note').filter({ hasText: 'This policy only.' })).toBeVisible()
  await page.getByLabel('Action').fill('s3:GetObject')
  await page.getByLabel('Resource ARN (optional)').fill('arn:aws:s3:::example-bucket/reports/q1.csv')
  await page.getByRole('button', { name: 'Check', exact: true }).click()
  await expect(page.getByTestId('access-result')).toHaveAttribute('data-decision', 'conditional')
  await expect(page.getByTestId('access-result')).toContainText('Allowed only if the conditions in Statement 1 (S3ReadOnly) are met.')

  await page.getByLabel('Action').fill('iam:CreateUser')
  await page.getByLabel('Resource ARN (optional)').fill('')
  await page.getByRole('button', { name: 'Check', exact: true }).click()
  await expect(page.getByTestId('access-result')).toHaveAttribute('data-decision', 'explicit-deny')
})

test('invalid JSON shows a readable error', async ({ page }) => {
  await page.goto('./')
  await page.locator('textarea').fill('{ "Version": ')
  await page.getByRole('button', { name: 'Parse', exact: true }).click()
  await expect(page.getByText(/^Invalid JSON: /)).toBeVisible()
})

test('a dense policy stays readable: fitted to width, shown from the top', async ({ page }) => {
  const actions = (svc: string, ops: string[]) => ops.map(op => `${svc}:${op}`)
  await pastePolicy(page, {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: actions('s3', ['GetObject', 'PutObject', 'ListBucket', 'DeleteObject']), Resource: ['arn:aws:s3:::example-bucket-one', 'arn:aws:s3:::example-bucket-one/*'] },
      { Effect: 'Allow', Action: actions('dynamodb', ['GetItem', 'PutItem', 'Query', 'Scan']), Resource: 'arn:aws:dynamodb:us-east-1:111122223333:table/example-table' },
      { Effect: 'Allow', Action: actions('lambda', ['InvokeFunction', 'GetFunction']), Resource: 'arn:aws:lambda:us-east-1:111122223333:function:example-fn' },
      { Effect: 'Allow', Action: actions('sqs', ['SendMessage', 'ReceiveMessage', 'DeleteMessage']), Resource: 'arn:aws:sqs:us-east-1:111122223333:example-queue' },
      { Effect: 'Allow', Action: 'sns:Publish', Resource: 'arn:aws:sns:us-east-1:111122223333:example-topic', Condition: { StringEquals: { 'aws:SourceAccount': '111122223333' } } },
      { Effect: 'Allow', Action: actions('kms', ['Decrypt', 'GenerateDataKey']), Resource: '*' },
      { Effect: 'Deny', Action: actions('iam', ['CreateUser', 'DeleteRole', 'PutRolePolicy']), Resource: '*' },
      { Effect: 'Deny', Action: 'organizations:LeaveOrganization', Resource: '*', Condition: { Bool: { 'aws:MultiFactorAuthPresent': false } } },
    ],
  })
  await expect(page.getByText('Statement 8: Deny')).toBeAttached()
  const fit = await nodesOutsideView(page)
  expect(fit.total).toBe(40)
  expect(fit.outsideHorizontally).toBe(0)
  expect(await nodesUnderControls(page)).toBe(0)
  expect(await viewZoom(page)).toBeGreaterThanOrEqual(0.75)
  expect(await itemTextPx(page)).toBeGreaterThanOrEqual(11)
  // The first item is visible at the top; the rest is reachable by scrolling.
  await expect(page.getByText('s3:GetObject', { exact: true })).toBeInViewport()
})

test('fitting keeps the diagram clear of the zoom controls', async ({ page }) => {
  // Mid-size policy: tall enough to fit to width, with the Policy node level
  // with the controls in the bottom-left corner.
  const actions = (svc: string, ops: string[]) => ops.map(op => `${svc}:${op}`)
  await pastePolicy(page, {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: actions('s3', ['GetObject', 'PutObject', 'ListBucket', 'DeleteObject']), Resource: ['arn:aws:s3:::example-bucket-one', 'arn:aws:s3:::example-bucket-one/*'] },
      { Effect: 'Allow', Action: actions('dynamodb', ['GetItem', 'PutItem', 'Query', 'Scan']), Resource: 'arn:aws:dynamodb:us-east-1:111122223333:table/example-table' },
      { Effect: 'Allow', Action: actions('sqs', ['SendMessage', 'ReceiveMessage', 'DeleteMessage']), Resource: 'arn:aws:sqs:us-east-1:111122223333:example-queue' },
      { Effect: 'Allow', Action: 'sns:Publish', Resource: 'arn:aws:sns:us-east-1:111122223333:example-topic' },
      { Effect: 'Deny', Action: actions('iam', ['CreateUser', 'DeleteRole', 'PutRolePolicy']), Resource: '*' },
    ],
  })
  await expect(page.getByText('Statement 5: Deny')).toBeAttached()
  await expect(page.locator('.graph-container foreignObject', { hasText: 'Version: 2012-10-17' })).toBeInViewport()
  expect(await nodesUnderControls(page)).toBe(0)
  // The fit button restores the same clear layout after panning.
  await page.mouse.move(1100, 500)
  await page.mouse.wheel(0, 300)
  await page.getByRole('button', { name: 'Fit to view' }).click()
  await expect.poll(() => nodesUnderControls(page)).toBe(0)
})

test('PNG and PDF export capture the whole diagram regardless of pan and zoom', async ({ page }) => {
  await loadSample(page)

  // Move the view away from the default first.
  await page.mouse.move(1000, 500)
  await page.mouse.down()
  await page.mouse.move(1350, 750, { steps: 5 })
  await page.mouse.up()
  await page.getByRole('button', { name: 'Zoom in' }).click()
  await page.getByRole('button', { name: 'Zoom in' }).click()

  // Expected size: graph bounds + 24px padding per side, at pixel ratio 2.
  const bounds = await page.evaluate(() => {
    const s = document.querySelector('.graph-container svg') as SVGSVGElement
    return { w: Number(s.dataset.graphWidth), h: Number(s.dataset.graphHeight) }
  })
  const expectedW = Math.ceil(bounds.w + 48) * 2
  const expectedH = Math.ceil(bounds.h + 48) * 2

  const [pngDownload] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Export PNG' }).click(),
  ])
  expect(pngDownload.suggestedFilename()).toBe('policy-visualizer.png')
  const png = fs.readFileSync(await pngDownload.path())
  expect(png.subarray(0, 8)).toEqual(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))
  expect(Math.abs(png.readUInt32BE(16) - expectedW)).toBeLessThanOrEqual(4)
  expect(Math.abs(png.readUInt32BE(20) - expectedH)).toBeLessThanOrEqual(4)

  const [pdfDownload] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Export PDF' }).click(),
  ])
  expect(pdfDownload.suggestedFilename()).toBe('policy-visualizer.pdf')
  const pdf = fs.readFileSync(await pdfDownload.path())
  expect(pdf.subarray(0, 5).toString()).toBe('%PDF-')
  expect(pdf.length).toBeGreaterThan(10_000)
  expect(pdf.length).toBeLessThan(2 * 1024 * 1024)
  await expect(page.getByRole('alert')).toHaveCount(0)
})
