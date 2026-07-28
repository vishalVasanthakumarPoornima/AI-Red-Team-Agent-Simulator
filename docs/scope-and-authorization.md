# Scope and authorization

## Unified assessment enforcement

Phase 5 applies scope after deterministic normalization, again before run
creation, and for every plan scope target before any registered tool executes.
Redirects are separately revalidated. Active HTTP, Python, host, web, Ollama,
OpenAI-compatible, and Kali operations require a human-controlled
authorization statement of at least 12 characters. Model output cannot supply
authorization, change the target, add ports, or add steps. Deep-lab is limited
to loopback/configured lab scope and requires final interactive confirmation.

The deterministic `ScopePolicy` is the only scope decision layer used by the
CLI, API, adapters, and executor. Loopback is allowed by default. Lab CIDRs,
domains, and Kali aliases must be configured explicitly. Public targets remain
disabled unless every public-target control is deliberately satisfied.

Inspect policy without executing tools:

```bash
redteam scope show
redteam scope validate http://127.0.0.1:18080
redteam scope explain http://127.0.0.1:18080
```

Validation reports the original and normalized target, scheme, classification,
allow/deny result, policy rule, reason, and safe DNS evidence. Credential-bearing
URLs, metadata addresses, broadcast, multicast, link-local, unspecified,
unallowlisted private, and default-public destinations fail closed.

Every active assessment requires a statement written by the human operator:

```bash
redteam assess start \
  --kind python \
  --target tool_agent \
  --category prompt_disclosure \
  --authorization "I own this local synthetic target and authorize bounded testing."
```

The statement is tied to the exact normalized target and revalidated
immediately before the executor runs. A generated statement, model output,
environment-derived text, or `--yes` is not authorization. DNS changes and
redirects outside the authorization record are denied.

The wizard shows target metadata, exact scope, active/passive state, registered
operations, and budgets before final confirmation. Denial or cancellation
before that confirmation never reaches the executor and creates no run.

Dexter discovery and readiness use passive decisions and GET-only checks. The
complete plan validates every component scope before creating a run directory.
Active standard execution requires a human statement and final confirmation.
Deep-lab is limited to loopback or an explicitly allowed lab and requires a
real interactive confirmation; `--yes` cannot enable it. Redirects are not
automatically followed, and cross-host redirects or resolution changes fail
closed.

## Adaptive enforcement

Phase 6 planning receives only stable target identity, target kind, declared
capability names, registered categories/templates, evidence identifiers,
coverage gaps, prior prompt hashes, budgets, and immutable policy reminders.
It does not receive authorization text, credentials, destination URLs, local
paths, tool arguments, or raw evidence bodies.

Every model proposal is revalidated against the original human authorization,
normalized target, adapter capabilities, typed template registry, operation,
tool, prompt/request limits, mutation policy, and prior fingerprints. Attempts
to introduce URLs, shell commands, real-secret shapes, local paths,
destructive/exfiltration requests, unregistered tools, ports, paths, or
authorization are persisted as rejected proposals and never executed.

Resume requires a fresh human statement and refuses manifest, target, adapter,
or normalized-scope drift. Model output cannot mark an error as a pass, create
a finding, or overrule a deterministic stop decision.

## Reporting and safe sharing

Reporting never expands assessment scope and does not execute probes. Internal
reports retain authorized technical detail but still redact secrets.
Safe-share reports additionally alias personal names, email addresses, phone
numbers, hostnames, home-directory paths, SSH paths, and other
machine-specific identifiers. Authorization statements are represented only
by presence and bounded metadata; report output does not treat a model or
generated statement as authorization.
