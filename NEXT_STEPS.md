# Next Steps

This checklist is ordered for a safe, reproducible path from the current advanced prototype to a production-ready security lab. Do not expand active scanning or public exposure before the Immediate items are resolved.

## Immediate

- [ ] Confirm the allowed scan scope: loopback, lab CIDRs, SSH aliases, domains, ports, and whether public targets are ever permitted.
- [ ] Implement a centralized authorization/scope gate before every Kali or URL network/subprocess action.
- [ ] Require explicit, non-model-derived authorization acknowledgement for active scans.
- [ ] Block link-local, cloud metadata, multicast, credential-bearing, and unapproved destinations; revalidate redirects and resolved addresses.
- [ ] Secure or disable the public Render POST /invoke endpoints.
- [ ] Add authentication, quotas, bounded concurrency, and deadlines to any network-exposed service.
- [ ] Review the current dirty worktree and preserve the intended Kali web-app changes and untracked tests in a reproducible commit.
- [ ] Keep generated output, local .env files, and real credentials out of Git.

## Core functionality

- [ ] Replace the echo-only tool_agent with a safe, realistic dry-run tool agent.
- [ ] Add explicit tool schemas, capability declarations, approval requirements, and audit events.
- [ ] Make the natural-language Kali status intent execute the same real status path as the CLI.
- [ ] Define versioned typed schemas for assessment, run, probe, result, finding, event, and artifact records.
- [ ] Normalize ERROR, UNPARSED, exception, timeout, and HTTP failure handling across all workflows.
- [ ] Split red_team_assistant.py into intent parsing, policy, orchestration, and presentation modules.
- [ ] Split kali_url_attack.py into scope policy, transport, recon, payloads, evaluation, and persistence.
- [ ] Move SSH/tunnel helpers into a stable public transport module rather than importing private helpers.
- [ ] Create unique run directories and manifests instead of overwriting default assessment artifacts.
- [ ] Decide whether the Dexter and legacy vulnerable-agent modules should be supported, isolated fixtures, or removed.

## Security

- [ ] Add strict post-model intent validation using allowed enums and typed schemas.
- [ ] Ensure model output cannot grant itself Kali, public-network, or reporting privileges.
- [ ] Apply URL scheme, hostname, DNS/IP, redirect, and credential validation to registry, Ollama, and scan URLs.
- [ ] Add rate limits, per-principal quotas, concurrency limits, queue bounds, and 429/503 behavior.
- [ ] Keep local lab services loopback-only by default.
- [ ] Require TLS and documented trusted-proxy behavior for any public deployment.
- [ ] Add structured, redacted audit logs without full prompts by default.
- [ ] Sanitize URLs, query strings, command output, prompts, and responses before persistence or safe sharing.
- [ ] Define report permissions, retention, rotation, deletion, and safe-export policy.
- [ ] Document enrolled target modules as trusted code and isolate third-party targets in constrained processes.
- [ ] Add a threat model covering prompt injection, tool abuse, SSRF, model/provider exhaustion, report leakage, and supply chain.
- [ ] Add a dependency vulnerability and secret-scanning gate.

## Testing

- [ ] Add scope-policy tests for IPv4, IPv6, DNS, redirects, link-local, metadata, multicast, credentials, and allowed lab targets.
- [ ] Assert denied targets never reach SSH, subprocess, or HTTP tools.
- [ ] Add authentication and rate-limit tests for /invoke.
- [ ] Add one deterministic end-to-end test from CLI/assistant through service invocation and report validation.
- [ ] Build a labeled detector corpus with benign reflections, paraphrases, encoded payloads, and true disclosures.
- [ ] Measure detector false-positive and false-negative rates.
- [ ] Add malformed JSON, invalid UTF-8, body-size, timeout, handler exception, and concurrent-request tests.
- [ ] Add redaction tests for secrets embedded in URLs and variables without standard secret names.
- [ ] Add invalid PORT and timeout configuration tests.
- [ ] Add opt-in live Ollama, weather, Kali, and Render integration suites guarded by explicit flags.
- [ ] Add coverage reporting and an agreed minimum threshold.

## Production readiness

- [ ] Adopt pyproject.toml with a documented Python 3.13 support range.
- [ ] Lock and hash dependency versions; make clean installs reproducible.
- [ ] Add CI for unit tests, compile checks, lint, type checks, coverage, secret scan, and dependency audit.
- [ ] Centralize typed configuration and fail startup with actionable validation errors.
- [ ] Replace public ThreadingHTTPServer deployment with a bounded production server and graceful shutdown.
- [ ] Add request IDs, latency, outcome, saturation, dependency-health metrics, and alerts.
- [ ] Add health checks that distinguish process liveness from model/tool readiness.
- [ ] Add deployment staging, smoke, rollback, and incident-response runbooks.
- [ ] Decide whether Docker packaging is required; add it only after the runtime boundary is defined.
- [ ] Validate the Render blueprint only in an authenticated staging environment.

## Documentation

- [ ] Add .env.example containing names and safe placeholders only.
- [ ] Create docs/architecture.md from the architecture and execution-flow sections in PROJECT_CONTEXT.md.
- [ ] Create docs/threat-model.md with assets, trust boundaries, abuse cases, and mitigations.
- [ ] Document HTTP request/response schemas and authentication behavior.
- [ ] Document target enrollment, the run_agent contract, and trusted-code implications.
- [ ] Document report schemas, retention, redaction guarantees, and ERROR/UNPARSED semantics.
- [ ] Add a contributor guide with setup, tests, style, and safety rules.
- [ ] Add a supported model/provider/version matrix.
- [ ] Add an authorized Kali lab setup and troubleshooting guide without real host/key values.
- [ ] Add deployment hardening and rollback documentation.
- [ ] Add a license after the distribution decision is made.

## Portfolio improvements

- [ ] Build a read-only dashboard for run history, findings, traces, and coverage.
- [ ] Never let the dashboard start active scans without explicit authorization and review.
- [ ] Map findings to OWASP LLM/agent risk categories and relevant control frameworks.
- [ ] Add realistic, safe agent/tool scenarios with human approval points.
- [ ] Add benchmark charts showing detector accuracy, coverage, and reliability rather than only PASS counts.
- [ ] Track and declare the showcase/white-paper generator dependencies if those scripts become supported.
- [ ] Make portfolio artifacts reproducible from committed source and sanitized sample data.
- [ ] Add a short demo script that uses loopback-only targets and produces a fresh run-scoped report.
- [ ] Publish a clear limitations statement: bounded tests are evidence, not proof of security.

