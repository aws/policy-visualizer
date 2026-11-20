# Policy Visualizer for AWS

> **Disclaimer:** This tool is sample code provided for educational purposes. It is not intended for production use without additional security review and testing. Its findings are a starting point and do not replace IAM Access Analyzer policy validation or your own review.

A browser-based tool for reading AWS IAM policy JSON. Paste or upload a policy
(or AWS CLI output such as `get-bucket-policy`, `get-role`, or
`organizations describe-policy`, a CloudFormation template, or a URL-encoded
policy) and it renders:

- an interactive node diagram of the policy, its statements, and their actions,
  resources, principals, and conditions;
- plain-English summaries of each statement;
- a permissions table;
- findings from offline checks: public and cross-account principals,
  wildcard and sensitive actions, `iam:PassRole` on any role, S3 actions that
  don't match their bucket or object ARNs, `NotAction`/`NotResource`/
  `NotPrincipal` with Allow, condition operator pitfalls (`ForAllValues`,
  `ForAnyValue`, wildcards in `StringEquals`, `IfExists`), old or missing
  `Version`, duplicate `Sid` values, and size limits. Findings adjust to the
  policy type (identity, resource-based, trust, SCP/RCP, permissions
  boundary). Trust policies and SCPs/RCPs are detected from exact wrapper
  keys (`AssumeRolePolicyDocument`, and `Policy.Content` from
  `organizations describe-policy`), identity, resource-based, and trust
  policies from the contents, and a permissions boundary only when you pick
  it. You can change the type. For SCPs, RCPs, and permissions boundaries
  the "grants too much" checks are off, and the findings say so. Findings can be copied as
  Markdown. These checks cover common mistakes only and do not replace IAM
  Access Analyzer policy validation;
- a comparison with a previous version of the policy: added and removed
  statements, actions, resources, principals, conditions, and findings. A
  statement counts as changed when anything in it other than its Sid
  changes, so moving an action, principal, or condition to another
  statement shows up even though the policy-wide lists stay the same;
- a "Check access" view that shows whether this one policy allows an action
  on a resource. It lists conditions and policy variables instead of
  evaluating them and does not consider other policies;
- an Optimize view that builds a narrower policy from the permissions you mark
  as needed. Deny, `NotAction`/`NotResource`, and statements with more
  action and resource pairs than the table shows are kept as written, and the
  policy `Version` is kept as it was. Review the result, and validate it with
  IAM Access Analyzer, before you use it;
- PNG and PDF export of the diagram;
- an optional redaction mode that replaces account IDs, resource names, Sids,
  condition values, and unrecognized element names with placeholders across
  the page: the diagram, tables, findings, comparison, Check access results,
  Copy as Markdown, and PNG and PDF exports. It also hides the pasted policy
  text and masks the Check access resource and caller fields. Kept as they
  are: action names, service principals, Region names in condition values,
  and condition keys (except tag names, as in `aws:ResourceTag/<key>`, and
  web identity provider hosts, which are replaced). In an ARN, wildcards and
  known policy variables are kept: documented `aws:` keys such as
  `${aws:username}`, `saml:` keys, `sts:RoleSessionName` and
  `sts:SourceIdentity`, and the keys of public identity providers. A tag key
  inside a variable is replaced (`${aws:PrincipalTag/KEY-1}`), and a default
  value follows the condition value rules, so `true`, `false`, short
  numbers, Regions, and `<service>.amazonaws.com` names stay and anything
  else is replaced. Any other `${...}` text is replaced, keeping its shape
  (`${KEY-1:KEY-2}`, `${aws:KEY-3}`). The partition, service, and Region
  fields are kept whatever they contain. The account field is replaced
  unless it is `aws` (AWS managed policies), keeping only wildcards and
  policy variables. The first part of the resource, which is normally its
  type (`table`, `role`), is kept. For an ARN whose resource
  starts with a name instead, such as an SNS subscription
  (`...:<topic>:<id>`), that name is shown. Redaction changes only what is
  shown: analysis uses the real policy, and the Optimize download contains
  the real values. It is best effort, so check the output before you share
  it.

## Runs entirely in your browser

The app is a static single-page application. It does not send your policy
anywhere: parsing, analysis, rendering, and export all happen locally in the
browser. There is no backend, no telemetry, and nothing is stored.

## Requirements

- Node.js 22.12 or newer
- npm

## Run locally

```bash
npm ci
npm run dev
```

Then open the URL printed by Vite (default `http://localhost:3000`). Use
**Load Sample Policy** to try it with the bundled `public/sample-policy.json`,
or paste your own policy JSON.

## Build

```bash
npm run build
```

The production build is written to `dist/`. Preview it with:

```bash
npm run preview
```

### Base path

The Vite base path defaults to `./`, so the build works from a web root, a
subfolder, or GitHub Pages without changes. To set an explicit base path, pass
`VITE_BASE` at build time:

```bash
VITE_BASE=/my-subpath/ npm run build
```

### Hosting

If you host the build publicly, serve it over HTTPS and set a full
`Content-Security-Policy` header at the web server or CDN, including
`frame-ancestors 'none'` (or set `X-Frame-Options: DENY`) so other sites
can't frame the page. The build includes a `<meta>` policy (see
`vite.config.ts`), but a `<meta>` policy cannot set `frame-ancestors`.

## Test and lint

```bash
npm test       # run unit tests once
npm run lint   # eslint, zero warnings allowed
```

### Browser tests

The browser tests in `e2e/` use [Playwright](https://playwright.dev/). They
build the app, serve the production build on `127.0.0.1`, and check the
diagram, analysis panel, optimized policy download, and PNG/PDF export. They
also fail if the page makes any request outside its own origin.

```bash
npx playwright install chromium   # once, downloads the test browser
npm run test:e2e
```

To use an installed Google Chrome instead of the downloaded browser, set
`PW_CHANNEL=chrome`. To test a subfolder deployment such as GitHub Pages, set
`E2E_BASE=/policy-visualizer/`.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
