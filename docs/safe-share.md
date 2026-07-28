# Safe-share reports

Internal reports retain authorized technical context but always redact
secrets. Safe-share reports additionally remove or alias personal and
machine-specific values. Original run artifacts and evidence are never
rewritten.

The deterministic redactor covers secret-valued fields, API keys, bearer and
OAuth tokens, authorization headers, cookies, sessions, password-like fields,
private-key material, credential URLs, sensitive query parameters, email
addresses, phone numbers, cloud-account identifiers, home and SSH paths, and
local absolute paths. Stable aliases keep a report internally coherent.

```bash
redteam reports export RUN_ID \
  --safe-share \
  --destination ./portfolio-report
```

The output directory contains selected report formats and its own
`report_manifest.json`. A visible banner identifies safe-share mode. Evidence
is represented by sanitized bounded excerpts and references, never copied in
bulk. Review any exported report before publication because organization-
specific sensitive patterns may require additional policy.
