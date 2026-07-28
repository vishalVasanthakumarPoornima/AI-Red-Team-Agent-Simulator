# Security and Threat Model

## Trust boundaries

The human operator and local configuration are trusted to define authorization.
Target content, model output, HTTP responses, OpenAPI documents, tool output,
and discovered process metadata are untrusted. Python target modules execute in
the current process and are therefore trusted code; process isolation remains a
hardening opportunity.

## Scope controls

- Loopback is allowed by default; configured lab CIDRs and Kali aliases are
  opt-in.
- Credential-bearing URLs, metadata services, link-local, multicast,
  unspecified, global broadcast, and configured-network broadcast addresses are
  denied.
- All DNS answers must classify within scope. Authorization is invalidated if
  resolution changes before execution.
- Active work requires a human statement. Public scope additionally requires
  configuration enablement, an exact/suffix domain allowlist, `--public`, and
  interactive confirmation. The API cannot supply that interaction.
- Redirects are never followed automatically by adapters. `validate_redirect`
  exists for explicit revalidation and rejects unapproved cross-host or changed
  resolution.

## Model and tool boundaries

Local models may select and edit prompts for registered probe templates only.
They cannot create target URLs, authorize scope, change budgets, generate a
shell command for execution, or overrule policy/detector results. Kali actions
are fixed templates with typed arguments; arbitrary model-provided commands are
not accepted.

## API controls

The API is loopback-only, uses a constant-time bearer-token comparison, imposes
body size and per-client rate limits, bounds worker concurrency, validates all
request schemas, and restricts downloadable artifact names. `/health` is the
only unauthenticated endpoint and exposes no secret.

## Sensitive data

Configuration displays never reveal API token values or the Kali key path.
Artifacts redact secret-like fields, authorization/cookie headers, configured
environment secret values, URL credentials, and query strings. Authorization
statements are persisted only as a redacted marker. Run directories use mode
0700 and files use 0600 when supported by the host filesystem.

## Residual risks

- Imported Python targets are not sandboxed.
- Rule-based findings require human review and can be false positive/negative.
- Listener inventory can expose local process names in private artifacts.
- The API task registry and rate limiter are process-local, not durable or
  distributed.
- Legacy commands remain for compatibility and do not all use the new artifact
  layout; prefer `redteam` for new work.
- Dependency risk must be reassessed whenever the lock changes.

Report security issues privately. Do not include real secrets or production
target data in an issue or portfolio artifact.
