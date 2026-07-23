# Scope and authorization

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
