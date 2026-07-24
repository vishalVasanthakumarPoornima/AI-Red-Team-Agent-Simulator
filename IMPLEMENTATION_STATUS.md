# Implementation Status

Last updated: 2026-07-23

## Phase 3 status

Phase 3 is complete. The supported CLI is now a modular Typer/Rich application
with a terminal menu, full non-interactive commands, reusable presentation and
query utilities, safe assessment orchestration, run/report browsing,
configuration inspection, Kali readiness, diagnostics, JSON envelopes, and
centralized exit codes.

The suite contains 158 passing tests: the existing 125 Phase 1–2 tests and 33
new Phase 3 tests. Normal tests require no Internet, Ollama, Docker daemon,
Kali host, root privileges, public systems, or real interactive terminal.

### Phase 3 capabilities

- `redteam` opens the menu only when both input and output are terminals.
  Non-interactive no-argument execution prints help and never hangs.
- The menu displays cached inventory freshness, agent/model/listener counts,
  wildcard exposure, Kali state, recent runs, and configuration warnings
  without silently refreshing integrations.
- `inventory`, `models`, `agents`, and `services` are nested command groups
  with summary/show/list/filter operations. Legacy Phase 2 JSON commands keep
  their original raw payloads.
- `assess start` and the wizard expose only Python, compatible HTTP,
  OpenAI-compatible, and Ollama adapters already supported by the application
  service. Host, generic web, and Dexter expansion are visibly planned and
  cannot create placeholder runs.
- Scope validation and a human-written authorization statement are required
  before execution. `--yes` never creates authorization, and public targets
  still require a real interactive confirmation.
- Run browsing tolerates corrupt, partial, and missing optional artifacts.
  Authorization text is summarized, manifests are hash-checked, events can be
  emitted as explicit JSON Lines, and artifact paths cannot escape a run.
- Report browsing exposes only formats that already exist. Export sanitizes
  text artifacts, rejects traversal, does not fabricate PDF/HTML, and refuses
  overwrite without `--overwrite`.
- Kali status is configuration-only by default. `kali check --live` is the
  explicit fixed-script readiness path and never scans a target or starts a
  tunnel.
- `doctor` reports PASS/WARN/FAIL/SKIP results for runtime, dependencies,
  configuration, paths, inventory cache, integrations, existing runs, artifact
  writing, and terminal capabilities. `--strict` maps warnings to exit 8.
- New data commands emit stable JSON envelopes with no ANSI sequences.
  Expected errors are structured and traceback-free; debug tracebacks are
  sanitized. Exit codes 0–9 and 130 are centralized.

### Phase 3 modules

- `redteam_platform/cli/app.py`, `context.py`, `errors.py`, `exit_codes.py`
- `redteam_platform/cli/formatting.py`, `progress.py`, `prompts.py`, `queries.py`
- `redteam_platform/cli/commands/{menu,inventory,assess,runs,kali,scope,config,doctor,help}.py`
- `redteam_platform/run_browser.py`
- `redteam_platform/diagnostics.py`
- `redteam_platform/__main__.py`

`redteam_platform/cli.py` remains a compatibility path while imports and the
installed entry point resolve the modular `redteam_platform.cli` package.

### Phase 3 boundaries

Phase 3 does not implement the later Dexter assessment, generic host/web
expansion, adaptive-engine expansion, enterprise report redesign, or FastAPI
migration. Existing lower-level compatibility adapters remain in the
repository, but the Phase 3 wizard does not advertise those later workflows as
available.

## Phase 2 checkpoint

Phase 2 was checkpointed before Phase 3 as commit `50c61df` with all 125
baseline tests passing.

## Phase 2 scope

Phase 2 is implemented as a passive-first, typed inventory subsystem. No
address-range scanning, assessment prompt execution, model mutation, container
mutation, tunnel creation, arbitrary command execution, or FastAPI migration
was added. The existing CLI and API received only the compatibility handlers
and type filters needed to expose inventory.

The complete suite now contains 125 passing tests: the existing 76 Phase 1
tests plus 49 Phase 2 test methods.

## Phase 2 features implemented

### Typed inventory and stable identity

- `redteam_platform/inventory/models.py` defines versioned schemas for
  snapshots, items, listeners, process metadata, services, agents, Ollama
  endpoints/models, Docker containers, Kali readiness, tools, evidence,
  errors, correlations, summaries, adapter runs, and cache metadata.
- Enums cover item type, status, discovery source, confidence, health, tool
  state, adapter state, and refresh mode.
- `redteam_platform/inventory/platform.py` generates stable hashed identifiers
  from normalized non-secret identity fields. Credentials, queries, fragments,
  secrets, and volatile timestamps do not participate.
- IPv4/IPv6 addresses and base URLs are normalized before identity,
  correlation, policy decisions, or persistence.

### Passive adapters

- `listeners.py` reads TCP and optional UDP listener tables through `psutil`,
  then safely falls back to `lsof` on macOS or `ss` on Linux. Access-denied
  process metadata is reported without dropping the listener.
- Process names, executable paths, owners, and redacted command summaries are
  collected where permissions allow. Loopback, private-interface, wildcard,
  public-interface, and unknown reachability are distinguished.
- `agents.py` reuses literal target enrollment, imports only enrolled modules,
  reports import/contract health without invoking prompts, reads
  `agent_registry.json`, and performs bounded GET-only metadata classification.
- Compatible project agents, the multi-agent lab, OpenAI-compatible services,
  FastAPI applications, protected services, and unknown HTTP services have
  separate evidence-based classifications. A generic metadata `name` alone is
  insufficient to classify an AI agent.
- `ollama.py` records configured endpoints without making a request by
  default. An explicit live opt-in reads version, installed models, and running
  models from the supported Ollama metadata endpoints. Installed and running
  states remain independent.
- `docker.py` optionally reads `docker ps` JSON metadata. It does not start,
  stop, inspect, execute in, or pull a container.
- `kali.py` validates the exact configured alias and local SSH binary without
  connecting by default. Its live opt-in sends one fixed allowlisted readiness
  script that reports OS/tool metadata and never scans a target.

### Network policy and correlation

- `http_probe.py` applies the Phase 1 `ScopePolicy` before each request, uses
  short timeouts and byte limits, validates JSON, denies redirects, and treats
  401/403 as protected-service evidence.
- Public or otherwise denied destinations never reach the HTTP transport.
- `correlation.py` deterministically relates listeners, services, registry
  records, Python targets, Ollama endpoints, models, and Docker port mappings.
  It retains underlying items and evidence, records reasons/confidence, and
  avoids port-only merging across network namespaces.

### Orchestration, cache, artifacts, and interfaces

- `InventoryService.collect` continues through adapter failures, returns typed
  partial errors, records adapter duration/state, deduplicates stable
  identities, sorts output, correlates relationships, and produces summary
  counts.
- `InventoryCache` writes schema-versioned snapshots atomically with mode
  `0600` where supported, validates TTL and source-host metadata, marks stale
  data, and rejects corrupt or incompatible cache data.
- `InventoryService.attach_to_run` writes a sanitized atomic
  `inventory.json`, registers its SHA-256 and size in `manifest.json`, and
  refuses overwrite without an explicit refresh.
- Minimal compatibility commands are available: `inventory`, `models`,
  `agents`, `services`, and `kali-status`, including JSON, refresh, cached,
  Docker, Kali, strict, and explicit live-readiness flags where applicable.
- The existing authenticated API inventory route returns the Phase 2 snapshot;
  its target/model filters now use Phase 2 typed item identities.

## Phase 2 files added

- `redteam_platform/inventory/__init__.py`
- `redteam_platform/inventory/models.py`
- `redteam_platform/inventory/platform.py`
- `redteam_platform/inventory/cache.py`
- `redteam_platform/inventory/http_probe.py`
- `redteam_platform/inventory/ollama.py`
- `redteam_platform/inventory/listeners.py`
- `redteam_platform/inventory/agents.py`
- `redteam_platform/inventory/docker.py`
- `redteam_platform/inventory/kali.py`
- `redteam_platform/inventory/correlation.py`
- `redteam_platform/inventory/service.py`
- `docs/discovery.md`
- `docs/configuration.md`
- `tests/test_inventory_stable_ids.py`
- `tests/test_inventory_ollama.py`
- `tests/test_inventory_listeners.py`
- `tests/test_inventory_agents.py`
- `tests/test_inventory_docker_kali.py`
- `tests/test_inventory_cache_correlation.py`
- `tests/test_inventory_service.py`

## Existing files modified for Phase 2

- `.env.example`
- `config.example.toml`
- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/OPERATIONS.md`
- `IMPLEMENTATION_STATUS.md`
- `redteam_platform/settings.py`
- `redteam_platform/artifacts.py`
- `redteam_platform/cli.py`
- `redteam_platform/api.py`
- `redteam_platform/service.py`
- `tests/test_platform_api.py`
- `tests/test_platform_configuration.py`

The pre-existing `redteam_platform/inventory.py` compatibility implementation
was not deleted or rewritten. Python resolves the new inventory package for the
Phase 2 application path. Existing dirty-worktree files unrelated to Phase 2
were preserved.

## Phase 2 tests

The 49 Phase 2 tests cover:

- stable identifiers, credential exclusion, endpoint differences, and IPv6
- Ollama availability, version, installed/running separation, empty lists,
  endpoint-versus-Ollama unavailability, invalid/oversized metadata, timeout,
  redirects, scope denial, redaction, and live opt-in
- macOS/Linux `psutil`, `lsof`, `ss`, TCP, UDP, IPv4, IPv6, wildcard/private/
  loopback classification, access denial, unsupported platforms, and command
  redaction
- enrolled targets, import errors, registry records, project and multi-agent
  services, OpenAI compatibility, FastAPI, protected/unknown services,
  conservative agent classification, and absence of `/invoke` POSTs
- deterministic correlation, ambiguity, namespace separation, evidence
  preservation, and deduplication
- Docker absent/daemon/permission/no-container/running/stopped/port-mapping
  states and mutation-command exclusion
- Kali unconfigured/missing SSH/allowed/denied/timeout/tool/version states and
  scan/arbitrary-command exclusion
- cache read/write, TTL, stale state, schema mismatch, corruption, atomic
  preservation, restrictive modes, and redaction
- successful and partial orchestration, adapter status/duration, sorting,
  summaries, force/cached modes, error preservation, and run-manifest artifact
  registration
- Phase 2 API snapshot and typed target/model compatibility filters
- validation of every new Phase 2 configuration field

Normal tests use mocks, fixtures, temporary directories, and loopback-only
service fixtures. They require no public network, Docker daemon, Kali host,
root access, or running Ollama.

## Phase 2 commands run

```bash
.venv/bin/python -m unittest discover -s tests
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m compileall redteam_platform
RUN_SERVICE_SMOKE=1 ./scripts/validate.sh
git diff --check
.venv/bin/redteam inventory --json
.venv/bin/redteam inventory --json --refresh
.venv/bin/redteam inventory --json --cached
.venv/bin/redteam inventory --json --include-docker
.venv/bin/redteam inventory --json --live-ollama
.venv/bin/redteam models --json
.venv/bin/redteam models --json --live
.venv/bin/redteam agents --json
.venv/bin/redteam services --json
.venv/bin/redteam kali-status --json
```

The required validation gate passed with Python 3.13.7, 125 unit tests, full
compilation, six enrolled targets, a 6 PASS deterministic scanner result, all
three loopback service-smoke applications, and a clean whitespace check.

The explicit loopback Ollama smoke found Ollama 0.30.7, eight installed models,
zero running models, and did not load, execute, pull, unload, or delete a
model. Docker CLI was present but the daemon was unavailable; inventory
returned a valid partial snapshot. Kali was not configured and was reported as
such without an SSH connection.

## Phase 2 failures and warnings

- An early compatibility smoke used the obsolete `--no-docker` option. The
  correct safe default requires no Docker flag; documentation now uses
  `redteam inventory --json --refresh`.
- During implementation, the first loopback-only inventory smoke performed an
  Ollama metadata read before the explicit-live boundary was finalized. The
  default was corrected to no request, covered by a regression test, and the
  final live smoke used the documented `--live` opt-in. No public endpoint was
  contacted.
- `ruff` and `mypy` are declared optional development dependencies but are not
  installed in the current `.venv`, so their standalone checks were not run.
  The required validator skips them when unavailable.
- FastAPI tests emit a non-failing Starlette deprecation warning about the
  future `httpx2` test client.

## Remaining Phase 2 limitations

- macOS denied process-wide `psutil.net_connections`; the live smoke
  automatically used `lsof`, so some executable and command details were
  unavailable. This is reported as a partial adapter state.
- Listener reachability is a host-level inference; firewalls, routing, and
  separate container namespaces can change actual exposure.
- HTTP classification remains intentionally conservative. Authenticated
  services can be identified as protected but cannot be classified beyond
  available unauthenticated evidence.
- Docker inventory depends on an accessible local daemon. No daemon was
  available for live validation; deterministic mocked coverage passed.
- Kali live readiness was not run because no exact alias was configured.
- Reverse-tunnel capability remains unknown; Phase 2 does not create a tunnel
  to test it.
- Per-adapter listener caching is not implemented. The setting is validated and
  reserved; the complete snapshot cache implements the required TTL/stale
  behavior.
- On the case-insensitive macOS filesystem, the requested
  `docs/architecture.md` path resolves to the existing
  `docs/ARCHITECTURE.md`; that document was updated in place.

## Phase 2 status

All Phase 2 acceptance criteria are implemented and validated. Phase 2 is
complete. Later-phase interactive CLI redesign, Dexter attack implementation,
adaptive attack work, and FastAPI migration were not started by this phase.

## Phase 1 baseline

Phase 1 is complete. Work after the user's scope correction was limited to:
typed configuration, versioned shared schemas, centralized scope and
authorization policy, persisted authorization records, unique run IDs,
isolated/atomic run artifacts, defense-in-depth integration with existing
active Kali/URL entry points, and deterministic tests.

Later-phase files already present in the dirty working tree were preserved and
were not advanced as part of this Phase 1 completion pass.

## Phase 1 features implemented

### Centralized typed configuration

- `redteam_platform/settings.py` uses `pydantic-settings`.
- Configuration precedence is TOML file, `.env`, process environment, then
  explicit overrides.
- Safe defaults bind to loopback, deny public targets, use bounded timeouts,
  and store run artifacts under `reports/runs`.
- Validation covers hostnames/IP addresses, ports, HTTP(S) endpoints, timeout
  and retention bounds, CIDRs, allowed domains, Kali aliases, report/cache
  paths, configured agents, Ollama endpoints, and Dexter endpoints/paths.
- Invalid configuration raises `ConfigurationError` with field-specific
  messages.
- `sanitized_settings` never returns API-token values or the Kali key path.
- `.env.example` and `config.example.toml` contain placeholders only.

### Versioned shared schemas

- `redteam_platform/schemas.py` defines versioned Pydantic contracts for
  `Target`, `Service`, `Agent`, `LocalModel`, `AuthorizationRequest`,
  `AuthorizationDecision`, `AuthorizationRecord`, `AssessmentRequest`,
  `Probe`, `ToolInvocation`, `ToolResult`, `Finding`, `AssessmentEvent`,
  `RunManifest`, `RunSummary`, and `ArtifactRecord`.
- Compatibility aliases preserve the earlier `ArtifactEntry` and
  `ArtifactManifest` names.
- `schema_from_legacy` and `schema_to_legacy` support incremental migration
  from existing dictionaries.

### Canonical authorization and scope policy

- `redteam_platform/scope_policy.py` is the canonical policy module.
- Loopback IPv4/IPv6 is always permitted by default.
- Configured lab CIDRs and explicitly configured Kali aliases are permitted.
- Public targets are denied unless configuration, allowlist, explicit mode,
  interactive confirmation, and a human statement all agree.
- Credential-bearing URLs, unsupported schemes, metadata IPs, link-local,
  multicast, unspecified, limited/configured broadcast, unconfigured private,
  and unspecified public destinations fail closed.
- URLs, hosts, ports, IDNA hostnames, IPv4, and IPv6 are normalized.
- Every DNS response is classified; resolution errors fail closed and
  resolution changes invalidate authorization.
- Decisions include normalized target, classification, reason(s), policy rule,
  resolved-address evidence, and policy identifier.
- Authorization sources are restricted to human CLI, API, or configuration
  inputs. Model-produced authorization is rejected by both schema and policy.

### Persisted authorization and run artifacts

- Authorization records include run ID, original/sanitized target, normalized
  target, requested profile, scope classification, sanitized human statement,
  typed policy decision, authorization source, and timestamp.
- Run IDs combine a UTC timestamp with 128 bits of UUID randomness.
- `RunArtifacts` creates a new directory with `exist_ok=False`, preserving every
  existing run.
- JSON/text artifacts use same-directory temporary files, `fsync`, and atomic
  `os.replace`.
- Run/evidence directories use mode `0700` and files use `0600` where supported.
- Manifests hash every persisted artifact and record start/end, status, stop
  reason, tools, models, sanitized scope, authorization ID, and errors.
- New platform runs use `reports/runs/<run_id>/` for authorization, events,
  findings, evidence, Markdown/JSON reports, summary, and manifest.

### Existing integrations changed

- `kali_url_attack.run_kali_url_attack` authorizes both the original target URL
  and Kali SSH alias before tunnel, SSH, remote command, recon, or probe code.
- `kali_agent_attack.run_kali_agent_attack` authorizes the loopback agent
  service and Kali alias before local subprocess/server/tunnel execution.
- `ai_red_team_cli.py` requires a human `--authorization` statement for active
  Kali commands and policy-checks Kali status aliases.
- `red_team_assistant.py` can receive a human-provided statement only through
  `REDTEAM_AUTHORIZATION_STATEMENT`; absent authorization fails closed.
- `tests/test_kali_url_attack.py` supplies explicit local test authorization
  and a configured synthetic Kali alias.
- `redteam_platform/service.py` reuses the authorization run ID for the artifact
  directory.
- `redteam_platform/adaptive.py` supplies lifecycle/tool/model/scope data to the
  Phase 1 manifest writer.
- `scripts/validate.sh` compiles `redteam_platform` and retains all existing
  validation behavior.

## Files added for Phase 1

- `.env.example`
- `config.example.toml`
- `pyproject.toml`
- `redteam_platform/__init__.py`
- `redteam_platform/settings.py`
- `redteam_platform/schemas.py`
- `redteam_platform/scope_policy.py`
- `redteam_platform/artifacts.py`
- `tests/test_platform_configuration.py`
- `tests/test_platform_schemas.py`
- `tests/test_platform_artifacts.py`
- `tests/test_scope_policy.py`

## Files modified for Phase 1 integration

- `requirements.txt`
- `ai_red_team_cli.py`
- `kali_agent_attack.py`
- `kali_url_attack.py`
- `red_team_assistant.py`
- `redteam_platform/adaptive.py`
- `redteam_platform/service.py`
- `scripts/validate.sh`
- `tests/test_kali_url_attack.py`
- `IMPLEMENTATION_STATUS.md`

## Tests

The complete suite contains 76 passing tests, including deterministic Phase 1
coverage for:

- IPv4/IPv6 loopback and configured lab CIDRs
- denied public, private, link-local, multicast, unspecified, broadcast, and
  cloud-metadata destinations
- credentials, schemes, multi-answer DNS, resolution errors, rebinding, and
  allowed-domain suffix rules
- human-only authorization
- prevention of HTTP, SSH, subprocess, tunnel, and Kali execution after denial
- configuration validation, source precedence, and secret-safe display
- schema serialization, strict parsing, and dictionary migration
- unique runs, existing-run preservation, atomic writes, permission modes,
  redaction, artifact hashes, and complete lifecycle manifests

Normal tests use local fixtures, fake DNS resolvers, mocks, temporary
directories, and loopback-only service fixtures. They do not access external
network targets.

## Commands run

```bash
.venv/bin/python -m compileall redteam_platform kali_url_attack.py kali_agent_attack.py ai_red_team_cli.py red_team_assistant.py
.venv/bin/python -m unittest discover -s tests -v
RUN_SERVICE_SMOKE=1 ./scripts/validate.sh
.venv/bin/python -m unittest discover -s tests -v
git diff --check
.venv/bin/redteam --json assess run --kind python --target tool_agent --authorization 'I own this local synthetic target and authorize bounded testing.' --category prompt_disclosure --rounds 1 --probes 1 --model-calls 0 --duration 30
```

All required commands completed successfully on the final validation pass:
76 tests passed, loopback service smoke passed, compilation passed, target
discovery found six explicit targets, deterministic scanner smoke returned
6 PASS / 0 FAIL / 0 ERROR, and `git diff --check` returned no output.
The final local-only Phase 1 artifact smoke also passed with one probe, no
errors, a unique 128-bit-suffix run ID, all required run files, ten hashed
artifact records, and complete lifecycle manifest fields.

## Failures encountered

The first `RUN_SERVICE_SMOKE=1 ./scripts/validate.sh` attempt passed all 76 tests
but stopped during compilation because `scripts/validate.sh` omitted a line
continuation before `redteam_platform`. The script was corrected; the complete
validation command then passed.

The test runner emits a non-failing Starlette deprecation warning stating that
its current `httpx` test-client integration will move to `httpx2`.

## Remaining Phase 1 limitations

- SSH configuration aliases cannot be DNS-resolved without interpreting the
  user's SSH configuration. They are therefore allowed only by exact explicit
  alias allowlist; unconfigured aliases fail before SSH.
- Python target modules remain trusted in-process code. Process isolation is a
  later hardening phase.
- `events.jsonl` appends and fsyncs one complete record at a time; JSON artifact
  replacements are atomic, but the event stream is intentionally append-only.
- Restrictive permissions are best effort on filesystems that do not implement
  POSIX mode bits.
- Existing legacy fixed-path reports are retained for compatibility. New
  platform runs use isolated run directories; historical files are not
  migrated automatically.
- No public target, real Kali host, Dexter deployment, or external model
  endpoint was contacted during Phase 1 validation.

## Phase 1 status

Phase 1 acceptance criteria are implemented and covered by deterministic tests.

## Phase 4 — First-class Dexter integration

Implemented in `redteam_platform/dexter/`:

- Versioned deployment, component, capability, readiness, plan, probe, result,
  finding, evidence, coverage, Kali, and summary models.
- Multiple configured deployments and conservative Phase 2 correlation for
  repository targets, HTTP/FastAPI metadata, listeners, processes, Docker,
  Ollama, and supporting services.
- Passive readiness plus deterministic passive, standard, and deep-lab
  profiles with visible ordered steps, fixed budgets, synthetic-only data, and
  deep-lab interactive confirmation.
- Fixed AI, API, fake-tool, synthetic memory, retrieval, service, rate-limit,
  and optional registered Kali checks.
- Typed deduplicated findings, explicit incomplete coverage, lifecycle
  handling, Phase 1 run artifacts, and Markdown/JSON Dexter reports.
- `redteam dexter discover|list|show|health|plan|assess`, interactive
  selection, JSON envelopes, progress, and `assess --kind dexter` routing.
- A disposable loopback fixture plus deterministic configuration, discovery,
  readiness, planning, authorization, probe, evaluation, Kali, coverage,
  artifact, report, CLI, and end-to-end tests.

Phase 4 does not mark general host/web adapters, adaptive attack planning,
global enterprise report redesign, or a full FastAPI migration as complete.
Live Dexter, Ollama, Docker, and Kali checks remain opt-in.
