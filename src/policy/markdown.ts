// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { Finding } from './findings'
import { guardrailNotice, POLICY_TYPES, type PolicyType } from './policyType'

export interface MarkdownOptions {
  policyType: PolicyType
  typeDetected?: boolean
  statements: number
  charCount: number
  sizeLimit?: number
  transform?: (text: string) => string
}

// Table cells can't hold line breaks.
const flat = (t: string) => t.replace(/\r\n?|\n/g, ' ')

// Our own text, such as finding titles: escape every Markdown and HTML punctuation character.
const escaped = (t: string) => flat(t).replace(/[\\`*_{}[\]()<>#+!|~&]/g, '\\$&')

// Policy values go in code spans, since escaping alone still lets GitHub autolink URLs and
// @mentions. "|" still ends a table cell inside a code span, so it is escaped too.
function code(t: string): string {
  const v = flat(t)
  if (!v) return ''
  const longest = Math.max(0, ...(v.match(/`+/g) ?? []).map(run => run.length))
  const fence = '`'.repeat(longest + 1)
  const pad = /^[` ]|[` ]$/.test(v) ? ' ' : ''
  return `${fence}${pad}${v.replace(/(\\*)\|/g, (_, b) => `${b}${b}\\|`)}${pad}${fence}`
}

export function findingsMarkdown(findings: Finding[], o: MarkdownOptions): string {
  const tx = o.transform ?? ((t: string) => t)
  const type = POLICY_TYPES.find(t => t.value === o.policyType)?.label ?? o.policyType
  const size = o.sizeLimit
    ? `${o.charCount.toLocaleString('en-US')} of ${o.sizeLimit.toLocaleString('en-US')} characters`
    : `${o.charCount.toLocaleString('en-US')} characters`
  const lines = [
    '## Policy findings',
    '',
    `Policy type: ${type} · Statements: ${o.statements} · Size: ${size}`,
    '',
  ]
  const notice = guardrailNotice(o.policyType, !!o.typeDetected)
  if (notice) lines.push(`> ${escaped(notice)}`, '')
  if (!findings.length) {
    lines.push('No issues found by the offline checks.')
  } else {
    lines.push('| Severity | Finding | Statement | Detail |', '| --- | --- | --- | --- |')
    for (const f of findings) {
      const where = f.statement ? `${f.statement}${f.sid ? ` \\(${code(tx(f.sid))}\\)` : ''}` : 'Policy'
      lines.push(`| ${f.severity} | ${escaped(tx(f.title))} | ${where} | ${code(tx(f.detail))} |`)
    }
  }
  lines.push('', '_Generated offline by Policy Visualizer for AWS. These checks cover common mistakes only and do not replace IAM Access Analyzer policy validation._')
  return lines.join('\n')
}
