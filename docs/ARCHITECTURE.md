# Architecture

## Application boundaries

`redteam_platform` is the supported application layer. The existing CLI calls
`ApplicationService` directly; FastAPI is optional and delegates to the same
service. `ScopePolicy` is the mandatory authorization boundary before active
work. Adapters receive typed targets and authorization records, then reuse the
existing scanner and deterministic detectors where appropriate.

```mermaid
flowchart LR
    Human["Human operator"] --> CLI["Existing command-line interface"]
    Human --> API["Authenticated loopback FastAPI"]
    CLI --> App["ApplicationService"]
    API --> App
    App --> Policy["ScopePolicy and authorization"]
    App --> Inventory["Unified passive inventory"]
    App --> Engine["Bounded adaptive engine"]
    Engine --> Planner["Deterministic or local model planner"]
    Planner --> Registry["Registered probe templates"]
    Engine --> Adapter["Typed target adapter"]
    Adapter --> Local["Python and local HTTP agents"]
    Adapter --> Lab["Authorized web, host, Dexter, or Kali lab"]
    Engine --> Detector["Deterministic evaluation"]
    Engine --> Artifacts["Run artifacts and manifest"]
    Artifacts --> Reports["Markdown, HTML, JSON, optional PDF"]
```

## Runtime flow

1. `redteam_platform.settings.load_settings` merges TOML, `.env`, process
   environment, and explicit overrides.
2. `ApplicationService.resolve_target` creates an adapter-specific `Target`.
3. `ScopePolicy.authorize` normalizes the destination, resolves every address,
   applies deny rules, and records a human statement.
4. `ApplicationService.run` revalidates authorization immediately before work.
5. The assessment engine executes within explicit budgets and registered
   actions.
6. Only registered probes reach a target adapter; model output cannot add
   tools, destinations, commands, or authorization.
7. `RunArtifacts` sanitizes and persists evidence, findings, reports, and
   hashes under a unique run ID.

Run directories are the durable assessment record; inventory uses a separate
JSON cache. Concurrent API execution uses an in-memory registry, so active task
state does not survive process restart.

## Phase 2 inventory architecture

The inventory subsystem is a library beneath the current application service
and CLI. Adapters return versioned items plus typed errors; they do not print,
persist, or terminate the complete operation. `InventoryService` owns
orchestration, deterministic correlation, stable sorting, summary generation,
cache persistence, and optional Phase 1 run attachment.

```mermaid
flowchart LR
    CLI["Existing CLI compatibility commands"] --> Orchestrator["InventoryService"]
    API["Existing authenticated API inventory route"] --> Orchestrator
    Orchestrator --> Platform["Platform and source-host identity"]
    Orchestrator --> Listeners["ListenerDiscovery"]
    Orchestrator --> Targets["PythonTargetDiscovery"]
    Orchestrator --> Registry["RegistryDiscovery"]
    Orchestrator --> Ollama["OllamaDiscovery"]
    Orchestrator --> HTTP["HTTPAgentDiscovery"]
    Orchestrator --> Docker["DockerDiscovery (optional)"]
    Orchestrator --> Kali["KaliDiscovery (optional)"]
    Listeners --> Correlator["InventoryCorrelator"]
    Targets --> Correlator
    Registry --> Correlator
    Ollama --> Policy["Phase 1 ScopePolicy"]
    HTTP --> Policy
    Kali --> Policy
    Policy --> Correlator
    Docker --> Correlator
    Correlator --> Snapshot["InventorySnapshot"]
    Snapshot --> Cache["Typed atomic standalone cache"]
    Snapshot --> Runs["Optional run inventory.json and manifest hash"]
```

## Module responsibilities

- `inventory/models.py`: versioned models, enums, evidence, errors, summaries,
  adapter status, cache metadata, and typed snapshot restoration.
- `inventory/platform.py`: platform detection, URL/address normalization,
  source-host hashing, and deterministic stable identifiers.
- `inventory/listeners.py`: `psutil` collection and safe macOS/Linux fallbacks.
- `inventory/agents.py`: enrolled Python targets, registry records, bounded
  service metadata discovery, and conservative agent classification.
- `inventory/http_probe.py`: scope-checked GET requests, redirect denial,
  response limits, JSON validation, and protected-service handling.
- `inventory/ollama.py`: configured endpoints, version, installed models, and
  running-model metadata.
- `inventory/docker.py`: optional read-only Docker CLI metadata.
- `inventory/kali.py`: exact-alias policy validation and opt-in fixed readiness
  command.
- `inventory/correlation.py`: deterministic deduplication and relationship
  evidence without an LLM.
- `inventory/cache.py`: schema/TTL validation and atomic restrictive writes.
- `inventory/service.py`: partial-failure orchestration, stable output,
  summaries, persistence, and run-manifest registration.

## Trust and dependency direction

Configuration and scope decisions come from Phase 1. Network and SSH adapters
cannot authorize themselves. Python enrollment marks repository code as trusted
for import, but inventory never imports unmarked files and never invokes attack
contracts. HTTP, OpenAPI, Docker, process, and remote Kali output are untrusted
data and are parsed into bounded schemas before use.

Stable IDs are hashes of normalized non-secret identity fields. Timestamps,
credentials, query strings, API keys, and authenticated URL user information
do not participate. Correlation preserves every underlying item and records a
separate reason/confidence relationship rather than destructively collapsing
uncertain identities.

## Phase 4 Dexter application services

The CLI calls `DexterDiscoveryService`, `DexterReadinessService`,
`DexterPlanService`, and `DexterAssessmentService`. Business rules remain under
`redteam_platform/dexter/`; handlers gather input and render typed results.
Discovery reuses Phase 2 snapshots, while assessment reuses Phase 1 scope,
authorization, schema, sanitization, and artifact APIs.

```mermaid
flowchart LR
    CLI["Phase 3 CLI"] --> Discovery["DexterDiscoveryService"]
    CLI --> Readiness["DexterReadinessService"]
    CLI --> Plan["DexterPlanService"]
    CLI --> Assessment["DexterAssessmentService"]
    Discovery --> Inventory["Phase 2 inventory"]
    Readiness --> Policy["Phase 1 ScopePolicy"]
    Plan --> Typed["Versioned Dexter models"]
    Assessment --> Policy
    Assessment --> Probes["Registered deterministic probes"]
    Assessment --> Artifacts["Phase 1 RunArtifacts"]
```

HTTP, inventory, Kali, readiness, clock, ID generation, cancellation, reporter,
and artifact creation boundaries are injectable for deterministic tests. The
local CLI path has no dependency on the optional FastAPI service.

## Phase 5 unified targets and deterministic assessments

Phase 5 adds `redteam_platform.targets` and
`redteam_platform.assessments` without replacing earlier services.

```mermaid
flowchart TD
  A["TargetDescriptor"] --> B["Deterministic registry"]
  B --> C["Dexter bridge"]
  B --> D["Python adapter"]
  B --> E["HTTP/OpenAI/Ollama adapter"]
  B --> F["Host/Web/Local adapter"]
  C --> G["Specialized Phase 4 services"]
  D --> H["Common planner and tools"]
  E --> H
  F --> H
```

```mermaid
flowchart LR
  A["Authorization"] --> B["target.json"]
  C["Phase 2 inventory"] --> D["inventory.json"]
  E["Plan"] --> F["assessment_plan.json"]
  G["Registered tool evidence"] --> H["evidence/"]
  H --> I["results and findings"]
  I --> J["coverage and summary"]
  J --> K["report.md and report.json"]
  K --> L["SHA-256 manifest"]
```

The common Phase 5 engine remains deterministic. Phase 6 layers the
`redteam_platform.adaptive_engine` package on top; it does not replace target
resolution, authorization, registered tools, or deterministic evaluation.

## Phase 6 bounded adaptive engine

```mermaid
flowchart TD
  A["Phase 5 target, baseline, evidence"] --> B["Coverage gap hypotheses"]
  B --> C["Minimized sanitized context + hash"]
  C --> D["Deterministic or local Ollama planner"]
  D --> E["Untrusted typed proposals"]
  E --> F["Schema/template/capability/scope/budget validator"]
  F -->|rejected| G["proposal_rejections.json"]
  F -->|accepted| H["Registered Phase 5 tool"]
  H --> I["Deterministic Phase 5 evaluator"]
  I --> J["Evidence + coverage + novelty deltas"]
  J --> K["Deterministic stopping policy"]
  K --> L["Adaptive artifacts + rebuilt manifest"]
```

The focused package separates configuration, models, roles, providers,
planning, hypotheses, templates, mutations, validation, execution, evaluation,
novelty, coverage, stopping, lifecycle, artifacts, service orchestration, and
benchmarking. Raw provider output never enters a tool invocation. The provider
can only produce a strict schema that is independently checked against human
configuration and a typed template registry backed by Phase 5 probes.

Adaptive records extend the existing unique run directory and its SHA-256
manifest. Benchmarks use `reports/benchmarks/` and synthetic cases, so their
metrics and recommendations cannot be confused with target findings.

## Phase 7 canonical reporting

```mermaid
flowchart LR
  A["Phase 1-6 run artifacts"] --> B["ArtifactNormalizer"]
  B --> C["CanonicalReport (Pydantic)"]
  C --> D["Deterministic findings, risk, coverage, remediation"]
  C --> E["JSON renderer"]
  C --> F["Markdown renderer"]
  C --> G["Self-contained HTML renderer"]
  C --> H["Optional PDF renderer"]
  D --> I["Comparison and retest"]
  E --> J["report_manifest.json"]
  F --> J
  G --> J
  H --> J
```

Normalization is the only compatibility boundary. Renderers never parse raw
run artifacts. Evidence references resolve beneath one run root, reject
symlinks and traversal, and expose only bounded sanitized excerpts. The
assessment manifest and report manifest are verified separately so report
rebuilds cannot silently rewrite assessment evidence.
