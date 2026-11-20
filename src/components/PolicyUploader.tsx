// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useState } from 'react'
import { ZodError } from 'zod'
import { describeParseError, InputTooLargeError, NoPolicyFoundError } from '../policy/parse'
import { loadPolicyText, MAX_INPUT_CHARS } from '../policy/input'
import type { ParsedPolicy } from '../policy/types'

// While `redacted` is on, the pasted text and where the policy was found
// (which can include CloudFormation resource names) are hidden.
export default function PolicyUploader({ onParsed, redacted = false }: { onParsed: (p: ParsedPolicy|null)=>void; redacted?: boolean }) {
  const [text, setText] = useState('')
  const [error, setError] = useState<string|null>(null)
  const [loading, setLoading] = useState(false);
  const [source, setSource] = useState<string | null>(null)

  const JSON_PLACEHOLDER = `{
            "Version": "2012-10-17",
            "Statement": [
                ...
   ]
}`;

  function handleParse(input: string) {
    const trimmed = input.trim()
    if (!trimmed) {
      setError('Please paste JSON or upload a file');
      onParsed(null);
      return;
    }
    try {
      const parsed = loadPolicyText(trimmed)
      setError(null)
      setSource(parsed.sourcePath
        ? `Found the policy at ${parsed.sourcePath}${(parsed.sourceCount ?? 1) > 1 ? ` (first of ${parsed.sourceCount} policies in the input)` : ''}.`
        : null)
      onParsed(parsed)
    } catch (e: unknown) {
      // Bad JSON and invalid policies are user input mistakes, shown in the
      // UI. Only log errors that aren't one of those.
      setSource(null)
      if (!(e instanceof SyntaxError) && !(e instanceof ZodError) && !(e instanceof NoPolicyFoundError) && !(e instanceof InputTooLargeError)) console.error(e)
      setError(describeParseError(e))
      onParsed(null)
    }
  }

  function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    // Reset so choosing the same file again (after editing it, or after
    // Clear) fires onChange again.
    e.target.value = ''
    if (!file) return
    // Check the size before reading, so a huge file is never loaded.
    if (file.size > MAX_INPUT_CHARS) {
      setError(`File is ${file.size.toLocaleString('en-US')} bytes; the limit is ${MAX_INPUT_CHARS.toLocaleString('en-US')}.`)
      onParsed(null)
      return
    }
    const reader = new FileReader()
    reader.onload = () => {
      const content = String(reader.result || '')
      setText(content)
      handleParse(content)
    }
    reader.onerror = () => {
      setError('Could not read the file. Please try again.')
      onParsed(null)
    }
    reader.readAsText(file)
  }

  async function loadSample(){
    try{
      setLoading(true);
      setError(null);
      // Load the bundled sample from a path relative to the app's base URL,
      // so it resolves whether the app runs at the root, in a subfolder, or
      // on GitHub Pages.
      const url = `${import.meta.env.BASE_URL}sample-policy.json`;
      const res = await fetch(url);
      if (!res.ok) throw new Error(`Could not load sample policy (HTTP ${res.status})`);
      const content = await res.text();
      setText(content);
      handleParse(content);
    }catch(e: unknown){
      console.error(e);
      setError(e instanceof Error ? e.message : 'Failed to load sample policy');
      onParsed(null);
    }finally{
      setLoading(false);
    }
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter'){
      e.preventDefault();
      handleParse(text);
    }
  }

  return (
    <div className="panel">
      <h3>Load Policy JSON</h3>
      <input type="file" accept=".json,.txt" onChange={onFile} />
      <div style={{height:8}}/>
      {redacted
        ? <div data-testid="policy-text-hidden" style={{ fontSize: 13, color: '#9aa7c3', border: '1px dashed #1c2442', borderRadius: 10, padding: 12, marginBottom: 4 }}>Policy text is hidden while redaction is on. Turn off Redact to edit it.</div>
        : <textarea placeholder={JSON_PLACEHOLDER} value={text} onChange={e=>setText(e.target.value)} onKeyDown={onKeyDown}/>}

      <div style={{display:'flex', gap:8, flexWrap:'wrap'}}>
        <button className="btn" onClick={()=>handleParse(text)}>Parse</button>
        <button className="btn secondary" onClick={()=>{ setText(''); onParsed(null); setError(null); setSource(null) }}>Clear</button>
        <button className='btn secondary' onClick={loadSample} disabled={loading}>
          {loading ? 'Loading...' : 'Load Sample Policy'}
        </button>
      </div>

      {error && <div style={{color:'#f76363', fontSize:13, marginTop:8}}>{error}</div>}
      {source && <div data-testid="policy-source" style={{color:'#5bb8ff', fontSize:13, marginTop:8}}>{redacted ? 'Found the policy inside the pasted input.' : source}</div>}
      <p className="note">Paste a policy or upload a file. AWS CLI output (such as get-bucket-policy or get-role), CloudFormation templates, and URL-encoded policies also work.</p>
    </div>
  )
}