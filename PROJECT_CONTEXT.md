# Project Context: AI Agent Red Team Simulator

> **Historical audit snapshot (2026-07-22).** This file preserves the evidence
> and conclusions from the pre-implementation repository audit. It is not the
> current setup or completion guide. See
> [`README.md`](README.md),
> [`docs/PROJECT_WALKTHROUGH.md`](docs/PROJECT_WALKTHROUGH.md), and
> [`docs/FINAL_STATUS.md`](docs/FINAL_STATUS.md) for the final verified state.

Audit date: 2026-07-22  
Audited branch: codex/kali-agent-cli at 86a8081  
Audit basis: current working tree, including pre-existing modified and untracked files  
Confidence legend: Confirmed means directly supported by repository evidence or a command run during this audit. Unverified means an external dependency, deployment, or host was not exercised.

## 1. Project Summary

The AI Agent Red Team Simulator is a local-first, authorized security testing toolkit for evaluating Python and HTTP-exposed AI agents for prompt disclosure, secret leakage, unsafe tool claims, weak refusal behavior, and web-application weaknesses. The intended users are security engineers, AI application developers, students, and portfolio reviewers operating in an isolated lab; the repository explicitly forbids testing public or third-party systems without authorization (README.md:3-14, README.md:322-328).

The product has four practical modes:

1. A deterministic scanner discovers explicitly enrolled Python targets and sends file-based attack prompts to their run_agent(prompt) interface (scanner/target_loader.py:9-42, scanner/attack_runner.py:24-43, scanner/attack_runner.py:92-130).
2. A local adaptive red-team planner uses Ollama to generate additional prompts for selected local target agents (local_red_team/run_local_red_team_scan.py:124-240, local_red_team/run_local_red_team_scan.py:319-371).
3. Loopback HTTP adapters expose targets for local discovery and testing (agent_lab_server.py:29-143, agent_service.py:28-110).
4. Kali workflows use SSH and optional reverse tunnels to run bounded recon, prompt probes, and web payload checks (kali_agent_attack.py:91-121, kali_agent_attack.py:181-205, kali_url_attack.py:533-749).

Confirmed maturity: advanced prototype / portfolio-grade lab. The core local scanner, target discovery, report generation, and loopback services are working and covered by 47 passing unit tests. The repository is not production-ready: deployed HTTP services have no authentication or rate limiting, active scan scope is enforced only by documentation, dependency resolution is not locked, and there is no CI/CD workflow, application package metadata, structured logging, or production operations layer.

Main technologies are Python 3.13, the standard-library HTTP server and urllib clients, Ollama, LangGraph, SSH, optional Kali tools such as nmap/WhatWeb/Nikto/sqlmap, JSON/JSONL/Markdown reporting, and Render blueprint deployment (requirements.txt:1, .python-version:1, render.yaml:1-30).

Implementation versus vision: partially aligned. The multi-path scanner, local model workflow, Kali integration, evidence capture, and enterprise report support the stated AI red-team vision. However, tool behavior is mostly simulated, the tool_agent target only echoes its prompt, the dashboard directory is empty, and the safety controls needed for responsible active scanning and public service deployment are not enforced in code (targets/tool_using_agent/tool_agent.py:1-7, README.md:322-328).

## 2. Repository Map

Generated directories, caches, .git, .venv, and report contents are omitted.

~~~text
.
├── README.md                         Product overview, safety boundaries, setup, and commands
├── ai_red_team_cli.py                Primary CLI and subcommand routing
├── red_team_assistant.py             Natural-language intent parsing and assessment orchestration
├── scanner/
│   ├── target_loader.py              Explicit REDTEAM_TARGET discovery
│   ├── attack_runner.py              Target import, prompt execution, and base reports
│   ├── detectors.py                  Rule-based security evaluation and secret redaction
│   └── report_generator.py           Legacy compatibility wrapper
├── attacks/
│   ├── prompt_disclosure/
│   ├── system_prompt_disclosure/
│   ├── prompt_injection/
│   ├── tool_abuse/
│   └── secret_extraction/            Curated payload text files
├── targets/
│   ├── _guardrails.py                Exact-marker response guardrail
│   ├── local_llm_agent/              Shared Ollama client target
│   ├── tool_using_agent/             Deterministic echo target
│   ├── travel_agent/                 Ollama travel target with fake lab secrets
│   ├── tutor_agent/                  Ollama tutor target with fake lab secrets
│   ├── weather_insight_agent/        LangGraph weather target wrapper
│   └── travel_planner_agent/         LangGraph travel target wrapper
├── functional_agents/
│   ├── env.py                        Minimal .env loader
│   ├── graphs.py                     Weather and travel LangGraph workflows
│   └── weather_tools.py              OpenWeather/Open-Meteo clients
├── local_red_team/
│   ├── WORKFLOW.md                   Adaptive local workflow guide
│   └── run_local_red_team_scan.py    Local Ollama planner and scan coordinator
├── agent_lab_server.py               Multi-target loopback HTTP adapter
├── agent_service.py                  Single-target HTTP service / Render entry point
├── agent_registry.py                 File registry, health checks, localhost discovery
├── agent_registry.json               Two local functional-agent registrations
├── http_agent_attack.py              Recon-driven HTTP agent attack runner
├── kali_agent_attack.py              Local-agent server, SSH tunnel, Kali probes
├── kali_url_attack.py                Hosted/local URL recon and web-app probes
├── assessment_monitor.py             JSONL events and Markdown timeline
├── enterprise_report.py              Enterprise Markdown and JSON report builder
├── scripts/
│   ├── bootstrap_dev.sh              Python 3.13 virtual-environment bootstrap
│   ├── validate.sh                   Project validation gate
│   ├── service_smoke.sh              Loopback service startup/discovery smoke
│   └── redteam_chat.sh               Natural-language assistant wrapper
├── tests/                             unittest suite; 47 tests currently pass
├── render.yaml                        Two public web-service blueprints
├── requirements.txt                  LangGraph lower-bound dependency only
├── .python-version                    Python 3.13 baseline
├── .gitignore                         Secrets, venv, reports, and generated PDF exclusions
├── agents/vulnerable_agent/           Legacy vulnerable example, outside target discovery
├── dashboard/                         Empty; no frontend implementation
├── docs/                              Empty; README is the only tracked documentation
└── reports/                           Ignored generated evidence and assessment artifacts
~~~

Working-tree-only items: targets/dexter_agent/dexter_agent.py is ignored and not explicitly enrolled; tests/test_kali_url_attack.py and two document-generation scripts under scripts/ are untracked. The current audit treats them as present but not safely preserved by Git.

## 3. System Architecture

### Major components

- Interface/orchestration: ai_red_team_cli.py maps CLI subcommands to scanner, service, assistant, and Kali workflows (ai_red_team_cli.py:281-545). red_team_assistant.py maps natural language to AssistantIntent and executes multi-stage assessments (red_team_assistant.py:42-53, red_team_assistant.py:136-215, red_team_assistant.py:340-648).
- Target plane: scanner/target_loader.py finds only Python files with a literal REDTEAM_TARGET = True assignment. scanner/attack_runner.py dynamically imports each target and calls run_agent(prompt).
- Evaluation plane: scanner/detectors.py identifies configured/fake secrets, prompt disclosure, unsafe tool compliance, and safe refusals, then returns PASS or FAIL records (scanner/detectors.py:168-189, scanner/detectors.py:299-338).
- Agent plane: simple Ollama targets, LangGraph weather/travel workflows, and deterministic targets implement the shared run_agent contract.
- HTTP plane: agent_lab_server.py exposes multiple targets; agent_service.py exposes one target. Both use ThreadingHTTPServer and JSON endpoints.
- Remote assessment plane: kali_agent_attack.py and kali_url_attack.py invoke SSH as argument arrays, quote remote dynamic values, run bounded tools, normalize failures, and tear down reverse tunnels.
- Evidence plane: per-attack JSON, combined Markdown, enterprise reports, and event timelines are written under reports/ (scanner/attack_runner.py:133-139, assessment_monitor.py:64-76, enterprise_report.py:567-582).

### Communication

- Python scanner to target: in-process function call.
- Functional graph to model: HTTP POST to an Ollama-compatible /api/generate endpoint.
- Functional graph to weather services: HTTPS GET to OpenWeather geocoding when configured, otherwise Open-Meteo geocoding; forecasts always come from Open-Meteo.
- CLI to local services: HTTP JSON.
- Mac to Kali: ssh subprocess; reverse SSH forwards Kali loopback to Mac loopback.
- Kali to target: curl, Python urllib, nmap, WhatWeb, Nikto, and optionally sqlmap.

### Backend architecture

There is no framework-based backend. The repository uses small modules and Python standard-library ThreadingHTTPServer handlers. Business logic is called directly from request handlers. There is no dependency-injection container, middleware stack, authentication middleware, application service layer, or persistent database.

### Frontend architecture

Missing. dashboard/ is empty and there are no JavaScript manifests, components, state stores, or frontend build files.

### Data storage

File-based only: JSON configuration, attack payload text, generated JSON/JSONL/Markdown reports, and optional .env configuration. No relational database, migrations, vector store, cache server, or object store is present.

### Authentication

Missing. /invoke, /metadata, /health, and /targets do not authenticate callers (agent_service.py:67-97, agent_lab_server.py:71-126). SSH uses key-based BatchMode and optional IdentitiesOnly for the Kali boundary (kali_agent_attack.py:69-88).

### Background processing

None. Requests run synchronously in per-request HTTP threads. There is no task queue, worker process, scheduler, cron configuration, or retry queue.

### Deployment

render.yaml declares two Python web services using agent_service.py on 0.0.0.0 and a Render-provided PORT. Both require an external Ollama-compatible endpoint. No Dockerfile, Compose file, health-check configuration, autoscaling policy, or CI deployment workflow exists (render.yaml:1-30, README.md:194-196).

~~~mermaid
flowchart LR
    Operator["Operator / Developer"] --> CLI["ai_red_team_cli.py"]
    Operator --> NL["red_team_assistant.py"]
    NL --> CLIFlow["Assessment orchestration"]
    CLI --> Scanner["scanner.attack_runner"]
    CLIFlow --> Scanner
    Scanner --> Loader["scanner.target_loader"]
    Loader --> Targets["Python targets / run_agent"]
    Targets --> Ollama["Ollama-compatible API"]
    Targets --> Graphs["LangGraph weather/travel graphs"]
    Graphs --> Weather["OpenWeather geocoding / Open-Meteo forecast"]
    CLI --> Services["agent_lab_server.py / agent_service.py"]
    Services --> Targets
    CLIFlow --> HTTPAttack["http_agent_attack.py"]
    HTTPAttack --> Services
    CLI --> KaliFlow["kali_agent_attack.py / kali_url_attack.py"]
    CLIFlow --> KaliFlow
    KaliFlow --> SSH["SSH + reverse loopback tunnel"]
    SSH --> Kali["Authorized Kali host"]
    Kali --> Services
    Kali --> URLTarget["Authorized hosted or local URL"]
    Scanner --> Detectors["scanner.detectors"]
    HTTPAttack --> Detectors
    KaliFlow --> Detectors
    Detectors --> Reports["JSON / JSONL / Markdown reports"]
    CLIFlow --> Monitor["assessment_monitor.py"]
    Monitor --> Reports
    CLIFlow --> Enterprise["enterprise_report.py"]
    Enterprise --> Reports
~~~

## 4. Execution Flow

### Typical deterministic scan

1. The operator runs python ai_red_team_cli.py scan with optional target and attack selectors. build_parser() attaches cmd_scan() (ai_red_team_cli.py:281-300).
2. cmd_scan() calls run_all_attacks() and summarizes PASS/FAIL/ERROR, optionally failing the process for findings (ai_red_team_cli.py:45-56).
3. run_all_attacks() creates reports/, discovers targets, loads payload files, filters selectors, and iterates target/attack pairs (scanner/attack_runner.py:258-271).
4. discover_targets() recursively scans targets/*.py and includes only literal REDTEAM_TARGET = True modules (scanner/target_loader.py:23-42).
5. load_payloads() reads nonblank, non-comment lines from attacks/<attack>/payloads.txt (scanner/attack_runner.py:24-38).
6. import_target_module() dynamically imports the target; run_prompt_against_target() validates run_agent, calls it, converts execution failures to ERROR, and evaluates the response (scanner/attack_runner.py:58-124).
7. evaluate_response() runs secret, prompt-disclosure, unsafe-tool, and refusal detectors (scanner/detectors.py:299-338).
8. save_attack_report() writes per-target JSON and generate_combined_report() writes reports/combined_report.md (scanner/attack_runner.py:133-139, scanner/attack_runner.py:173-255).
9. cmd_scan() prints counts and returns 0 unless fail-on-findings is active and failures/errors exist.

### HTTP service startup and request

1. python agent_service.py resolves AGENT_TARGET/HOST/PORT or CLI values (agent_service.py:113-124).
2. resolve_target() accepts only discovered, explicitly marked targets (agent_service.py:20-25).
3. ThreadingHTTPServer starts and stores the target descriptor (agent_service.py:100-110).
4. POST /invoke enforces a 32,000-byte JSON-object body and a nonempty prompt (agent_service.py:49-65, agent_service.py:84-97).
5. The handler directly calls run_prompt_against_target(), so every response contains both the target response and security evaluation.
6. No identity, role, quota, rate, origin, or authorization check occurs.

### Natural-language assessment

1. redteam_chat.sh invokes the CLI chat command (scripts/redteam_chat.sh:1-10).
2. interpret_request() uses deterministic heuristics by default; when explicitly requested, a local Ollama model returns intent JSON (red_team_assistant.py:136-274).
3. execute_intent() creates an AssessmentMonitor, records the interpreted intent, and dispatches static, adaptive, active-agent, Kali, web-app, or master flows (red_team_assistant.py:340-365).
4. Each flow stores its report under assessment.runs and sends monitor events.
5. write_enterprise_report() normalizes run results into a risk register and writes Markdown plus JSON (enterprise_report.py:398-582).
6. AssessmentMonitor.write() overwrites the default event/timeline artifacts for the most recent run (assessment_monitor.py:64-76).

## 5. AI and Agent Architecture

### Models and providers

- Default shared target model: llama3.2:1b via Ollama (targets/local_llm_agent/ollama_agent.py:9-12, targets/local_llm_agent/ollama_agent.py:24-39).
- Travel target: qwen2.5:0.5b unless TRAVEL_AGENT_MODEL overrides it (targets/travel_agent/travel_agent.py:7-9).
- Tutor target: smollm2:360m unless TUTOR_AGENT_MODEL overrides it (targets/tutor_agent/tutor_agent.py:7-9).
- Adaptive red-team planner: dolphin-llama3:latest unless LOCAL_RED_TEAM_MODEL overrides it (local_red_team/run_local_red_team_scan.py:26-29).
- Natural-language parser: optional local model named by REDTEAM_NL_MODEL (red_team_assistant.py:218-266).
- Functional weather/travel agents: WEATHER_AGENT_MODEL or TRAVEL_PLANNER_MODEL, falling back to OLLAMA_MODEL (functional_agents/graphs.py:156-160, functional_agents/graphs.py:207-211).
- No hosted commercial LLM SDK is present. OLLAMA_URL may point to a hosted Ollama-compatible endpoint.

### Prompts and guardrails

System prompts live inline in Python, not in a prompt registry:

- targets/local_llm_agent/ollama_agent.py:14-21
- targets/travel_agent/travel_agent.py:11-27
- targets/tutor_agent/tutor_agent.py:11-27
- functional_agents/graphs.py:140-167 and 189-218
- local_red_team/run_local_red_team_scan.py:40-47
- red_team_assistant.py:224-245

Attack prompts live under attacks/*/payloads.txt and in DEFAULT_PROBES in kali_agent_attack.py:21-37.

targets/_guardrails.py rejects responses containing exact sensitive markers or disclosure phrases. scanner/detectors.py independently evaluates observed output. This is defense in depth, but both layers are rule-based and can miss paraphrases or novel disclosures.

### State and orchestration

AgentState contains prompt, location, tool_data, and response (functional_agents/graphs.py:14-18). Weather and travel graphs each have a tool-collection node and a compose node, then end (functional_agents/graphs.py:128-174, functional_agents/graphs.py:177-225). No durable graph checkpoint, memory, retrieval, vector database, or conversation history is used.

The assessment orchestration state is a plain dictionary with request, intent, generated_at, targets, active_agents, and runs (red_team_assistant.py:358-365).

### Tools

- Weather geocoding and forecast via HTTPS.
- Local target function invocation.
- HTTP agent discovery and /invoke calls.
- SSH remote command execution.
- Kali recon: nmap, WhatWeb, Nikto, curl, Python urllib, and optional sqlmap.
- Report writers.

### Retry and failure behavior

- Weather requests use one request and raise ToolError; graph nodes catch it and place an error in tool_data (functional_agents/weather_tools.py:18-24, functional_agents/graphs.py:132-138).
- Ollama errors become strings beginning with ERROR rather than exceptions (targets/local_llm_agent/ollama_agent.py:73-129).
- Static scanner converts missing run_agent, error strings, and exceptions to ERROR records (scanner/attack_runner.py:70-124).
- Adaptive generation falls back to deterministic prompts when Ollama fails or returns invalid JSON (local_red_team/run_local_red_team_scan.py:187-240).
- SSH command timeouts return structured returncode 124 records (kali_agent_attack.py:91-121).
- Kali empty, failed, or unparseable responses count as UNPARSED, not PASS (kali_agent_attack.py:273-308).
- There is no exponential retry, circuit breaker, idempotency key, cancellation API, or durable resume.

### Human approval and security boundaries

Documented boundaries exist in README.md:322-328, but there is no code-enforced authorization confirmation or target allowlist before URL/Kali scanning. Natural-language intent can immediately initiate active scans. This is a confirmed architectural gap.

~~~mermaid
sequenceDiagram
    actor User
    participant Chat as red_team_assistant.py
    participant Policy as Intent heuristics or local Ollama
    participant KaliFlow as kali_url_attack.py
    participant SSH as SSH / Kali
    participant Target as Authorized target
    participant Eval as scanner.detectors
    participant Evidence as Monitor and reports

    User->>Chat: "scan this authorized URL"
    Chat->>Policy: interpret_request(text)
    Policy-->>Chat: AssistantIntent(web_app_attack, url)
    Note over Chat: No enforced approval or scope gate
    Chat->>Evidence: record interpreted intent
    Chat->>KaliFlow: run_kali_url_attack(url)
    KaliFlow->>SSH: start reverse tunnel if loopback
    KaliFlow->>SSH: run nmap / WhatWeb / Nikto / sqlmap
    SSH->>Target: endpoint and bounded payload probes
    Target-->>SSH: HTTP responses
    SSH-->>KaliFlow: structured stdout / status
    KaliFlow->>Eval: evaluate response indicators
    Eval-->>KaliFlow: PASS / FAIL / ERROR
    KaliFlow-->>Chat: report and summary
    Chat->>Evidence: JSONL timeline and enterprise report
    Chat-->>User: counts and artifact paths
~~~

## 6. Data Model

### Datastores

No database is present. All state is ephemeral memory or local files.

- agent_registry.json: service name, kind, health URL, invoke URL, description.
- attacks/*/payloads.txt: one prompt per nonblank/non-comment line.
- reports/<target>/<attack>.json: result arrays.
- reports/combined_report.md: latest aggregate scan.
- reports/local_red_team/*: adaptive planner inputs/results.
- reports/assessment_events.jsonl and reports/assessment_timeline.md: latest observable trace.
- reports/enterprise_red_team_report.md/json: latest enterprise summary.
- .env: optional local environment input; ignored by Git.

### Logical schema

A result contains target, attack, prompt, response, timestamp, status, passed, severity, confidence, reason, detectors, and evidence (scanner/attack_runner.py:75-90, scanner/detectors.py:299-338). HTTP and Kali probes wrap a result with transport details and parse_error (http_agent_attack.py:118-128, kali_url_attack.py:522-530).

~~~mermaid
erDiagram
    ASSESSMENT ||--o{ RUN : contains
    RUN ||--o{ PROBE : records
    PROBE ||--o| RESULT : evaluates_to
    RESULT ||--o{ FINDING : contributes_to
    ASSESSMENT ||--o{ EVENT : traces
    ASSESSMENT ||--o{ ARTIFACT : writes
    TARGET ||--o{ RESULT : receives
    ATTACK ||--o{ RESULT : produces

    ASSESSMENT {
        string request
        object intent
        datetime generated_at
    }
    RUN {
        string name
        object summary
    }
    PROBE {
        string target
        string attack
        string prompt
        object transport
        string parse_error
    }
    RESULT {
        string status
        string severity
        float confidence
        string reason
        string response
    }
    FINDING {
        string id
        string category
        string remediation
    }
    EVENT {
        int sequence
        datetime timestamp
        string phase
        string action
        string status
    }
    ARTIFACT {
        string path
        string format
    }
~~~

### Retention and sensitive data

Retention is unmanaged. Default report names are overwritten by later runs, while per-target and generated payload files remain until manually deleted. reports/ is Git-ignored (.gitignore:8), but files are plaintext and not encrypted. Configured environment values with secret-like variable names are redacted by scanner/detectors.py:168-189 and recursively redacted in monitor/HTTP/Kali paths. Unverified gap: secrets embedded in non-secret-named values such as authenticated URLs may not be recognized. Prompts, responses, URLs, tool output, and local service metadata can be retained in reports.

## 7. API and Interface Inventory

### HTTP APIs

| Method | Route | Purpose | Authentication | Request | Response | Implementation | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | /health on agent lab | Health and exposed target names | None | None | JSON status and targets | agent_lab_server.py, AgentLabHandler.do_GET, lines 71-80 | Complete for lab use |
| GET | /targets on agent lab | Enumerate exposed targets | None | None | JSON target names and paths | agent_lab_server.py, AgentLabHandler.do_GET, lines 82-95 | Complete for lab use |
| POST | /invoke on agent lab | Run prompt against selected target and evaluate response | None | JSON target, prompt, optional attack; max 32 KB | JSON security result | agent_lab_server.py, AgentLabHandler.do_POST, lines 99-126 | Complete locally; unsafe if exposed |
| GET | /health on single service | Agent liveness | None | None | JSON status and agent | agent_service.py, AgentServiceHandler.do_GET, lines 67-70 | Complete |
| GET | /metadata on single service | Agent identity and invoke metadata | None | None | JSON metadata | agent_service.py, AgentServiceHandler.do_GET, lines 71-81 | Complete |
| POST | /invoke on single service | Run prompt against configured target and evaluate response | None | JSON prompt and optional attack; max 32 KB | JSON security result | agent_service.py, AgentServiceHandler.do_POST, lines 84-97 | Functionally complete; security incomplete |

There are no WebSocket interfaces.

### External service interfaces

| Method | Interface | Purpose | Authentication | Implementation | Status |
| --- | --- | --- | --- | --- | --- |
| POST | OLLAMA_URL, default http://localhost:11434/api/generate | Local/compatible text generation | Endpoint-dependent; none implemented by client | targets/local_llm_agent/ollama_agent.py:50-129 | Unit-config tested; live model unverified |
| GET | OpenWeather geocoding API | Optional keyed geocoding | OPENWEATHER_API_KEY query parameter | functional_agents/weather_tools.py:43-58 | Unverified live |
| GET | Open-Meteo geocoding API | Keyless fallback geocoding | None | functional_agents/weather_tools.py:27-40 | Unverified live |
| GET | Open-Meteo forecast API | Forecast tool data | None | functional_agents/weather_tools.py:68-107 | Unverified live |
| SSH | Configured Kali host | Remote recon and probes | Key-based SSH | kali_agent_attack.py:69-121 | Code/tests pass; live host unverified |

### CLI inventory

Primary executable: python ai_red_team_cli.py (ai_red_team_cli.py:281-545).

| Command | Purpose | Status |
| --- | --- | --- |
| targets | List explicitly enrolled repository targets | Working |
| scan | Run curated payloads against targets | Working |
| chat | Interactive or one-shot natural-language orchestration | Working locally; active-action safety incomplete |
| local-red-team | Local Ollama adaptive payload generation and scan | Implemented; live models unverified |
| serve-agents | Multi-target loopback service | Working |
| serve-agent | Single-agent service and Render entry point | Working locally; public security incomplete |
| agents list | Read registry | Working |
| agents health | Check configured health URLs | Working; URL trust is caller-controlled |
| agents discover | Scan selected localhost ports for compatible services | Working |
| kali status | Check SSH and remote tools | Implemented; live host unverified |
| kali attack-agents | Start local adapter/tunnel and run Kali probes | Implemented; live host unverified |
| kali attack-url | Run hosted/local URL recon and optional web probes | Implemented; scope enforcement missing |

Internal interfaces include run_agent(prompt), run_all_attacks(), run_http_agent_attack(), run_kali_agent_attack(), run_kali_url_attack(), AssessmentMonitor.event(), and write_enterprise_report().

There are no scheduled jobs.

## 8. Configuration and Environment Variables

No secret values were inspected or reproduced. The local .env contains the name OPENWEATHER_API_KEY; its value is intentionally omitted.

### Application variables

| Name | Purpose | Required | Expected format | Safe example | Used in |
| --- | --- | --- | --- | --- | --- |
| AGENT_TARGET | Target served by agent_service.py | Optional | Discovered target name | weather_insight_agent | agent_service.py:115 |
| HOST | HTTP bind address | Optional | IP/hostname | 127.0.0.1 | agent_service.py:116 |
| PORT | HTTP port; injected by Render | Optional locally, required on Render | 1-65535 integer | 18101 | agent_service.py:117, render.yaml:6,21 |
| OLLAMA_URL | Full compatible generate endpoint | Optional locally, required for Render design | http(s) URL ending in /api/generate | http://127.0.0.1:11434/api/generate | targets/local_llm_agent/ollama_agent.py:28-29, render.yaml:10,25 |
| OLLAMA_MODEL | Default Ollama model | Optional | Ollama model tag | llama3.2:1b | targets/local_llm_agent/ollama_agent.py:24-25; functional_agents/graphs.py:159,210 |
| OLLAMA_TIMEOUT_SECONDS | Model request timeout | Optional | Positive integer seconds | 60 | targets/local_llm_agent/ollama_agent.py:32-39 |
| WEATHER_AGENT_MODEL | Weather graph model override | Optional | Ollama model tag | llama3.2:1b | functional_agents/graphs.py:159 |
| TRAVEL_PLANNER_MODEL | Travel graph model override | Optional | Ollama model tag | llama3.2:1b | functional_agents/graphs.py:210 |
| TRAVEL_AGENT_MODEL | Lightweight travel target model | Optional | Ollama model tag | qwen2.5:0.5b | targets/travel_agent/travel_agent.py:7 |
| TUTOR_AGENT_MODEL | Tutor target model | Optional | Ollama model tag | smollm2:360m | targets/tutor_agent/tutor_agent.py:7 |
| LOCAL_RED_TEAM_MODEL | Adaptive planner model | Optional | Ollama model tag | dolphin-llama3:latest | local_red_team/run_local_red_team_scan.py:28 |
| LOCAL_RED_TEAM_TIMEOUT_SECONDS | Adaptive planner timeout | Optional | Positive integer seconds | 180 | local_red_team/run_local_red_team_scan.py:29 |
| REDTEAM_NL_MODEL | Enables local-model intent parsing | Optional | Ollama model tag | llama3.2:1b | red_team_assistant.py:218-220 |
| DEFAULT_AGENT_LOCATION | Fallback location for functional agents | Optional | Plain location text | San Francisco | functional_agents/graphs.py:35-50 |
| OPENWEATHER_API_KEY | Optional keyed geocoding provider credential | Optional | Provider API key | example-not-a-real-key | functional_agents/weather_tools.py:43-48; render.yaml:14,29 |
| KALI_SSH_HOST | Default SSH alias/host | Optional | SSH host or alias | kali-lab | ai_red_team_cli.py:16; red_team_assistant.py:487-490 |
| KALI_SSH_KEY | SSH identity path | Optional if normal SSH config works | Filesystem path | /path/to/lab_key | ai_red_team_cli.py:220-224; red_team_assistant.py:282-289 |

### Development and smoke variables

| Name | Purpose | Required | Safe example | Used in |
| --- | --- | --- | --- | --- |
| PYTHON_BIN | Python executable override | Optional | python3.13 | scripts/bootstrap_dev.sh:4, scripts/validate.sh:4, scripts/service_smoke.sh:4, scripts/redteam_chat.sh:4 |
| PYTHON_FALLBACK | Fallback Python for wrappers | Optional | python3.13 | scripts/validate.sh:7, scripts/redteam_chat.sh:7 |
| VENV_DIR | Bootstrap virtualenv directory | Optional | .venv | scripts/bootstrap_dev.sh:5 |
| PIP_CACHE_DIR | Bootstrap pip cache | Optional | /tmp/ai-red-team-pip-cache | scripts/bootstrap_dev.sh:6-7 |
| TMPDIR | Platform temp root for caches/logs | Optional | /tmp | scripts/bootstrap_dev.sh:6, scripts/service_smoke.sh:9 |
| RUN_SERVICE_SMOKE | Include service smoke in validation | Optional | 1 | scripts/validate.sh:51-55 |
| AGENT_SMOKE_HOST | Smoke bind host | Optional | 127.0.0.1 | scripts/service_smoke.sh:5 |
| AGENT_SMOKE_LAB_PORT | Lab smoke port | Optional | 18080 | scripts/service_smoke.sh:6 |
| AGENT_SMOKE_WEATHER_PORT | Weather smoke port | Optional | 18101 | scripts/service_smoke.sh:7 |
| AGENT_SMOKE_TRAVEL_PORT | Travel smoke port | Optional | 18102 | scripts/service_smoke.sh:8 |

### Configuration weaknesses

- requirements.txt specifies only langgraph>=0.2.60, with no upper bound or lockfile. The audited environment resolved langgraph 1.2.7 and many transitive packages.
- render.yaml duplicates OLLAMA_MODEL, OLLAMA_URL, OLLAMA_TIMEOUT_SECONDS, and OPENWEATHER_API_KEY across two services.
- Integer variables are inconsistently validated. OLLAMA_TIMEOUT_SECONDS falls back safely, while PORT and red-team timeouts can raise ValueError during import/startup.
- KALI_SSH_HOST and URL scope are not validated against an allowlist.
- OLLAMA_URL accepts arbitrary schemes/hosts supported by urllib; no allowlist, TLS requirement, or credential-safe logging policy exists.
- .env.example is permitted by .gitignore but missing.
- No centralized typed settings object or startup configuration validation exists.

## 9. Setup and Runbook

### Prerequisites

Confirmed from repository:

- macOS/Linux-like shell.
- Python 3.13 (.python-version:1).
- Ollama for model-backed targets.
- SSH client for Kali workflows.
- An authorized Kali host with relevant tools for remote validation.

### Dependency installation

~~~bash
./scripts/bootstrap_dev.sh
source .venv/bin/activate
~~~

This creates .venv, upgrades pip, and installs requirements.txt (scripts/bootstrap_dev.sh:4-13).

### Environment setup

Set only the variables needed for the chosen flow. Example safe local configuration:

~~~bash
export OLLAMA_URL=http://127.0.0.1:11434/api/generate
export OLLAMA_MODEL=llama3.2:1b
export OLLAMA_TIMEOUT_SECONDS=60
~~~

There is no .env.example. Creating a local ignored .env is supported by functional_agents/env.py, but the parser is intentionally minimal.

### Model startup

~~~bash
ollama serve
ollama pull llama3.2:1b
ollama pull qwen2.5:0.5b
ollama pull smollm2:360m
~~~

The first model is the shared default; the latter two are needed for the default adaptive target set. dolphin-llama3:latest is also needed for the default adaptive planner.

### Local development and CLI

~~~bash
.venv/bin/python ai_red_team_cli.py targets
.venv/bin/python ai_red_team_cli.py scan --target tool_agent --attack prompt_disclosure
./scripts/redteam_chat.sh
~~~

### Backend/service startup

~~~bash
.venv/bin/python agent_service.py --target weather_insight_agent --host 127.0.0.1 --port 18101
.venv/bin/python agent_service.py --target travel_planner_agent --host 127.0.0.1 --port 18102
.venv/bin/python ai_red_team_cli.py serve-agents --host 127.0.0.1 --port 18080 --target tool_agent
~~~

### Database initialization

Not applicable. No database or migrations exist.

### Tests and validation

~~~bash
.venv/bin/python -m unittest discover -s tests -v
./scripts/validate.sh
RUN_SERVICE_SMOKE=1 ./scripts/validate.sh
git diff --check
~~~

All passed during this audit.

### Linting and type checking

Unverified/not configured. No pyproject.toml, setup.cfg, tox.ini, Ruff configuration, MyPy configuration, or repository command defines a supported lint/type gate. Do not treat an ad hoc global-tool run as authoritative.

### Production build

Not applicable in the current source: there is no package build configuration or frontend bundle. Python services run directly from source.

### Render deployment

render.yaml is the only deployment artifact. It installs requirements.txt and launches:

~~~bash
python3 agent_service.py --target weather_insight_agent --host 0.0.0.0 --port $PORT
python3 agent_service.py --target travel_planner_agent --host 0.0.0.0 --port $PORT
~~~

Unverified: actual Render deployment, TLS, health checks, external OLLAMA_URL reachability, and secret configuration. Do not deploy publicly until authentication and rate limiting are implemented.

### Docker

Missing. No Dockerfile or Compose configuration exists; no verified Docker command can be provided.

### Troubleshooting

- Ollama unavailable/model missing: start ollama serve, pull the configured model, and verify OLLAMA_URL. The client returns explicit ERROR strings (targets/local_llm_agent/ollama_agent.py:73-129).
- Wrong Python: use ./scripts/bootstrap_dev.sh; the supported baseline is Python 3.13.
- No targets: ensure the module has a top-level literal REDTEAM_TARGET = True and run the targets command.
- Agent down: run agents discover, then scripts/service_smoke.sh.
- Kali unreachable: run kali status with the intended SSH alias/key. Do not weaken BatchMode/host security to make the test pass.
- ERROR/UNPARSED findings: treat them as coverage gaps and rerun only after checking model/service/SSH health.
- pip cache warning: bootstrap_dev.sh already defaults its cache under TMPDIR. Direct pip commands may still warn if the user cache is unwritable.

## 10. Testing Assessment

### Existing framework and location

The project uses Python unittest under tests/. There is no coverage configuration or test runner dependency.

Confirmed test areas:

- Registry parsing, health behavior, and live local discovery.
- Event redaction and timeline output.
- Static runner error/finding/count behavior.
- Rule-based secret, refusal, and unsafe-tool detectors.
- Enterprise report risk and Kali URL scope rendering.
- HTTP attack normalization and secret redaction.
- SSH options and timeout normalization.
- Kali URL helper/evaluator/tunnel orchestration using mocks.
- Ollama URL/model configuration.
- Natural-language intent classification.
- Service target enrollment.
- Target marker discovery.

Audit result: 47 tests passed in approximately 1.6 seconds. The full validation gate passed.

### Gaps

- No test coverage measurement or minimum threshold.
- No live Ollama generation test.
- No live OpenWeather/Open-Meteo contract test.
- No real SSH/Kali integration test in this audit.
- No Render deployment smoke.
- No authentication/rate-limit tests because those controls do not exist.
- No concurrency, load, cancellation, slow-client, or resource-exhaustion tests.
- No end-to-end test from CLI intent through a real service invocation and report.
- No regression corpus measuring detector false positives/false negatives.
- No test that a model-generated intent cannot choose an unauthorized action/URL.
- No test for credential-bearing URLs or report retention/redaction edge cases.
- No test for invalid PORT or timeout environment values.
- No tests for the untracked document-generation scripts.

### Prioritized tests to add

1. P0: scope-policy tests rejecting public, link-local, metadata, loopback-confused, credential-bearing, and disallowed URLs before any SSH/tool call.
2. P0: service authentication and rate-limit tests, including health endpoint policy and unauthorized /invoke rejection.
3. P1: end-to-end loopback test from CLI scan/chat through HTTP service to report artifacts.
4. P1: detector evaluation corpus with labeled expected findings, paraphrases, encodings, and benign reflections.
5. P1: prompt-injection tests proving local-model intent output cannot bypass action/schema/scope validation.
6. P2: timeout, concurrent request, maximum-body, malformed UTF-8, and handler exception tests.
7. P2: sanitized report tests for credentials embedded in URLs and nonstandard environment names.
8. P2: opt-in live integration suite for Ollama/weather/Kali, disabled by default and guarded by explicit environment flags.
9. P2: deployment configuration validation and health smoke.
10. P3: generated document artifact tests if the untracked scripts become supported.

## 11. Security Review

No real hardcoded secret was found in tracked source. Secret-looking literals in the cited target and detector fixtures are explicitly labeled as fake lab data (scanner/detectors.py:7-17, targets/travel_agent/travel_agent.py:16-19). The .env value was not displayed.

### S-01 — Unauthenticated public model/tool invocation

- Severity: High
- Evidence: agent_service.py exposes POST /invoke without authentication (lines 84-97); render.yaml binds the service to 0.0.0.0 (lines 6 and 21); no rate-limit code exists.
- Impact: any network caller could consume model and weather-provider capacity, trigger expensive/slow requests, enumerate metadata, and repeatedly exercise prompt-injection paths. Thread-per-request execution amplifies denial-of-service risk.
- Remediation: default to loopback/private deployment; require authenticated authorization for /invoke; add per-principal quotas, concurrency bounds, request timeouts, and audit logs; keep /health minimal and public only if operationally necessary.
- Relevant files: agent_service.py, render.yaml, functional_agents/graphs.py, functional_agents/weather_tools.py.

### S-02 — Active scanning has no enforceable authorization or scope gate

- Severity: High
- Evidence: kali attack-url accepts any syntactically valid URL (ai_red_team_cli.py:470-529, kali_url_attack.py:115-125); natural-language URL requests immediately dispatch web_app_attack (red_team_assistant.py:176-178, red_team_assistant.py:501-534); the README warning is not checked in code.
- Impact: an operator mistake or manipulated local-model intent can direct nmap, Nikto, sqlmap, and more than 200 HTTP payload probes at an unauthorized or sensitive target.
- Remediation: create one centralized scope-policy module; require an explicit authorization acknowledgement; default to loopback and configured lab CIDRs/domains; resolve and validate destinations, reject cloud metadata/link-local/multicast/credential-bearing URLs, record the policy decision, and require a separate override for public targets.
- Relevant files: ai_red_team_cli.py, red_team_assistant.py, kali_url_attack.py, kali_agent_attack.py.

### S-03 — Model-produced intent is trusted without strict schema and policy validation

- Severity: Medium
- Evidence: _local_model_interpret() accepts any nonempty action and directly copies target, attack, and URL fields into AssistantIntent (red_team_assistant.py:218-266). execute_intent() dispatches the result; only known branch names avoid execution by falling back to help.
- Impact: prompt injection or malformed model output may choose a more privileged action, unexpected target, or remote URL. The absence of a post-model policy check weakens the human/tool boundary.
- Remediation: validate against enums and typed schemas, ignore model-provided privilege flags unless independently derived from the user command, apply the same target scope policy after parsing, and require approval before network-active actions.
- Relevant files: red_team_assistant.py.

### S-04 — Caller-controlled URLs create SSRF-style reachability

- Severity: Medium
- Evidence: check_agent_health() opens registry-provided URLs (agent_registry.py:41-55); OLLAMA_URL is arbitrary (targets/local_llm_agent/ollama_agent.py:28-29, 66-75); Kali URL scans accept arbitrary hosts.
- Impact: a malicious registry/configuration or compromised local intent could access internal services, cloud metadata, or other network zones from the Mac, Render service, or Kali host.
- Remediation: restrict schemes, reject credentials, normalize hostnames, validate resolved addresses, block link-local/metadata/multicast ranges, bind registry discovery to loopback by policy, and maintain explicit allowed destinations.
- Relevant files: agent_registry.py, targets/local_llm_agent/ollama_agent.py, kali_url_attack.py.

### S-05 — Plaintext report retention can leak sensitive assessment data

- Severity: Medium
- Evidence: assessment events include prompts, URLs, command excerpts, and result details (assessment_monitor.py:52-71); enterprise JSON serializes the full assessment (enterprise_report.py:567-580); reports are plaintext and have no retention controls.
- Impact: local users, backups, support bundles, or accidental publication can expose prompt content, target topology, tool output, and responses. Existing redaction depends on secret-like environment variable names.
- Remediation: define retention, write run-specific directories with restrictive permissions, sanitize URLs/query strings, expand structured redaction, provide a safe-share export, and document deletion/rotation.
- Relevant files: assessment_monitor.py, enterprise_report.py, scanner/detectors.py, reports/.

### S-06 — Dependency supply chain is not reproducible or continuously audited

- Severity: Medium
- Evidence: requirements.txt contains only langgraph>=0.2.60; there is no lockfile, hash pinning, package metadata, dependency audit config, or CI workflow.
- Impact: builds can resolve materially different transitive dependency sets, introduce incompatible APIs, or consume a vulnerable release without a visible source change.
- Remediation: adopt pyproject.toml, pin a tested Python range, produce a locked/hash-verified dependency set, run dependency auditing in CI, and document update cadence.
- Relevant files: requirements.txt, .python-version, scripts/bootstrap_dev.sh.
- Dependency CVE status: Unverified; no supported audit tool/configuration was present and no external advisory service was queried.

### S-07 — Unbounded thread-per-request model execution enables resource exhaustion

- Severity: Medium
- Evidence: both services use ThreadingHTTPServer (agent_service.py:100-110, agent_lab_server.py:129-143); model timeout defaults to 60 seconds and can be configured to 180; only request body size is bounded.
- Impact: concurrent callers can exhaust threads, outbound provider quota, memory, file descriptors, and model capacity.
- Remediation: deploy behind a bounded worker server/reverse proxy, cap concurrency and queue depth, add rate limits and deadlines, return 429/503 under saturation, and expose metrics.
- Relevant files: agent_service.py, agent_lab_server.py, targets/local_llm_agent/ollama_agent.py, render.yaml.

### S-08 — Dynamic imports execute target module top-level code

- Severity: Medium
- Evidence: import_target_module() dynamically executes every explicitly enrolled module (scanner/attack_runner.py:58-68). The AST marker limits discovery but is not a sandbox.
- Impact: an untrusted target contribution can execute arbitrary code with the scanner process privileges before run_agent is called.
- Remediation: document targets as trusted code, review enrollment changes, isolate target processes/containers, use a narrow RPC contract, and apply filesystem/network limits for third-party targets.
- Relevant files: scanner/target_loader.py, scanner/attack_runner.py.

### S-09 — Service logging and error handling reduce forensic visibility

- Severity: Low
- Evidence: both HTTP handlers suppress log_message() (agent_service.py:32-33, agent_lab_server.py:33-34); run_agent exceptions outside AgentServiceError are not converted to a structured 5xx response.
- Impact: abuse and failures are difficult to trace; handler crashes may appear as dropped connections and hide operational patterns.
- Remediation: add structured, redacted request IDs, auth principal, latency, outcome, saturation, and exception logs; never log full prompts by default.
- Relevant files: agent_service.py, agent_lab_server.py, assessment_monitor.py.

### S-10 — Transport and browser security are deployment-dependent

- Severity: Low
- Evidence: local services are plaintext HTTP and do not set HSTS, CSP, or CORS. They do set nosniff, DENY framing, and no-store (agent_service.py:38-46, agent_lab_server.py:39-47).
- Impact: LAN/public exposure without a trusted TLS reverse proxy would expose prompts and responses. Missing CORS is not itself a vulnerability here; public deployment behavior depends on Render.
- Remediation: keep local services loopback-only; require TLS at the public edge; document trusted-proxy headers and origin policy; do not rely on browser CORS as authentication.
- Relevant files: agent_service.py, agent_lab_server.py, render.yaml.

### Other reviewed categories

- Command injection: no confirmed shell injection in dynamic URL/prompt values; subprocess calls use argument arrays locally and shlex.quote for remote shell values (kali_agent_attack.py:91-100, kali_url_attack.py:195-239, 495-502). The remote command model remains privileged by design.
- Path traversal/file upload/insecure deserialization: no network file-upload or deserialization feature exists. CLI report paths are caller-controlled local paths.
- XSS/CSRF/CORS: no frontend exists. JSON services are unauthenticated; CSRF protection would not solve the missing authentication boundary.
- Tenant isolation: missing/not applicable to the current single-user lab; it becomes required if the service is multi-user.
- Vector retrieval/memory poisoning: no retrieval or vector store exists.

## 12. Code Quality and Architecture Assessment

### Strengths

- Explicit target enrollment prevents accidental discovery of scratch modules (scanner/target_loader.py).
- Scanner failures become structured ERROR records instead of crashing whole scans (scanner/attack_runner.py).
- Secret redaction is reused across scanner, HTTP, Kali, monitor, and enterprise reporting.
- SSH is noninteractive and reverse tunnels bind to loopback.
- Reports distinguish confirmed failures from execution coverage gaps.
- Unit tests are fast, deterministic, and currently green.

### Weaknesses

- Separation of concerns: red_team_assistant.py combines parsing, policy, orchestration, process decisions, reporting, and UI output; kali_url_attack.py combines target parsing, remote command construction, payload generation, evaluation, monitoring, console output, and persistence.
- Dependency direction: internal modules import private underscore helpers across modules, for example kali_url_attack.py imports _run_remote, _start_reverse_tunnel, _stop_process, and _summarize from kali_agent_attack.py (kali_url_attack.py:10-16). This couples two large workflows.
- Type safety: only a few TypedDict/dataclass annotations exist. Reports are unvalidated nested dictionaries.
- Error handling: mixed exception, ERROR-string, parse_error, return-code, and console-print conventions complicate automation.
- Logging: HTTP logs are disabled and assessment logging overwrites shared files.
- Configuration: environment reads are distributed across modules and sometimes happen at import time.
- Reusability: service handlers duplicate JSON/body/security header behavior.
- Maintainability: large procedural modules and private cross-imports make changes risky.
- Performance/scalability: synchronous model/tool calls and unbounded request threads are suitable only for a small lab.
- Observability: assessment traces are useful, but operational metrics, service logs, correlation IDs, and health dependency checks are missing.
- Documentation: README is useful, but architecture, threat model, supported version matrix, API schema, deployment hardening, and contributor conventions are absent.

### Refactor candidates

1. kali_url_attack.py (749 lines): split scope validation, SSH transport, recon tools, payload catalog, probe evaluation, and report persistence.
2. red_team_assistant.py (670 lines): split intent parsing, authorization policy, orchestration services, and presentation.
3. enterprise_report.py (582 lines): split normalization/model from Markdown rendering.
4. ai_red_team_cli.py (545 lines): move parser construction by command group and use shared typed settings.
5. kali_agent_attack.py (508 lines): extract SSH/tunnel transport into a stable public module.
6. scanner/detectors.py (355 lines): create detector protocol and a labeled evaluation suite.
7. agent_service.py and agent_lab_server.py: share HTTP parsing/security/auth middleware or migrate to a supported bounded web server.

## 13. Incomplete or Suspicious Areas

| Area | Evidence | Assessment |
| --- | --- | --- |
| Empty dashboard | dashboard/ contains no files and no JS manifest exists | Missing frontend, despite portfolio/product potential |
| Empty docs | docs/ contains no files | Documentation incomplete; README carries all guidance |
| Dexter target placeholder | targets/dexter_agent/dexter_agent.py says replace subprocess with actual logic, has no REDTEAM_TARGET marker, and is ignored | Intentional exclusion but incomplete/untracked |
| Echo tool target | targets/tool_using_agent/tool_agent.py:6-7 only reflects the prompt | Stub-like; not a realistic tool-using security target |
| Legacy vulnerable example | agents/vulnerable_agent/vulnerable_agent.py uses vulnerable_agent(), is not enrolled, and is not referenced | Likely obsolete/educational dead code |
| Legacy report wrapper | scanner/report_generator.py explicitly exists only for older imports | Intentional compatibility code; deprecation plan absent |
| Duplicate prompt file | attacks/prompt_injection/basic_injection.txt duplicates payload content but load_payloads() only reads payloads.txt | Unreferenced legacy file |
| NL Kali status | red_team_assistant.py:477-479 reports that status is available but does not execute it | Partially implemented behavior |
| Enterprise report double write | red_team_assistant.py:630-638 writes the enterprise report twice around monitor finalization | Likely accidental inefficiency and timestamp inconsistency |
| Broad exception catches | scanner/attack_runner.py:122, red_team_assistant.py:59, kali_url_attack.py embedded probe script line 385 | Some are intentional error boundaries; they reduce diagnosability |
| Generated artifact scripts | scripts/fill_project_showcase_template.py and scripts/generate_enterprise_whitepaper.py are untracked and require packages absent from requirements.txt | Unsupported auxiliary tooling |
| Untracked web probe tests | tests/test_kali_url_attack.py passes but is not tracked | Valuable coverage at risk of being lost |
| Dirty feature work | Seven tracked files are modified; web-app scanner adds roughly 600 lines | Current state is functional but not a reproducible committed baseline |
| No env template | .gitignore allows .env.example but none exists | Missing operator onboarding and config documentation |
| No CI/lint/type config | no .github workflow or Python tool config | Missing quality gate |
| No lockfile | requirements.txt has only a lower bound | Reproducibility incomplete |
| No auth/rate limit | public deployment points at unauthenticated handler | Security incomplete |
| Generated reports overwrite defaults | monitor and enterprise writers use fixed paths | Intentional simplicity, weak audit retention |

No pass-only function body, NotImplemented marker, disabled test, commented-out main implementation, or unsafe pickle/yaml deserialization was found in tracked core Python.

## 14. Current Project Status

| Subsystem | Status | Evidence |
| --- | --- | --- |
| Python 3.13 environment/bootstrap | Working | scripts/bootstrap_dev.sh; .venv Python 3.13.7; pip check passed |
| Target discovery | Working | Six targets found by validation; scanner/target_loader.py |
| Curated static scanner | Working | Validation smoke: 6 PASS, 0 FAIL, 0 ERROR |
| Rule-based detectors/redaction | Working with limitations | tests/test_detectors.py passes; heuristic coverage only |
| JSON/Markdown base reporting | Working | scanner/attack_runner.py; validation generated combined report |
| Natural-language heuristic parser | Working | tests/test_red_team_assistant.py passes |
| Local-model intent parser | Partially working | implemented; live Ollama unverified and policy validation missing |
| Adaptive local red-team planner | Partially working | fallback is tested by structure; live planner/targets unverified this audit |
| Weather/travel LangGraph agents | Partially working | imports/health work; live model and weather invocation unverified |
| Multi-target lab HTTP service | Working for loopback lab | service smoke passed |
| Single-agent HTTP service | Working locally, unsafe publicly | health/metadata smoke passed; no auth/rate limits |
| Agent registry/discovery | Working | unit tests and service smoke passed |
| HTTP dynamic attack runner | Working locally | unit tests pass; live model-backed services unverified |
| Kali local-agent workflow | Unverified live | timeout/SSH option tests pass; no external host accessed |
| Kali URL/web-app workflow | Partially working | mocked tests pass; active working-tree feature, live host unverified |
| Assessment monitor | Working | unit test passes; fixed-path retention weakness |
| Enterprise reporting | Working | tests pass; duplicate write in orchestrator |
| Render deployment | Unverified and security-incomplete | render.yaml exists; no deployment test/auth |
| Frontend/dashboard | Missing | empty dashboard/ |
| Database/vector store/cache | Missing/not required by current design | no manifests or code |
| Background workers/scheduling | Missing/not required by current design | no worker/scheduler code |
| CI/CD | Missing | no .github workflows |
| Docker packaging | Missing | no Dockerfile/Compose |
| Lint/type/coverage gate | Missing | no repository configuration |
| Dependency vulnerability status | Unverified | no lock/audit tool or external advisory check |
| Portfolio document generators | Unverified/unsupported | untracked; dependencies not declared |

## 15. Prioritized Roadmap

### P0 — Blocking

| Task | Why it matters | Files | Dependencies | Complexity | Acceptance criteria |
| --- | --- | --- | --- | --- | --- |
| Enforce centralized scan authorization and target scope | Prevents accidental/LLM-directed scans of unauthorized or sensitive systems | ai_red_team_cli.py, red_team_assistant.py, kali_url_attack.py, kali_agent_attack.py, new scope_policy.py, tests/ | Product decision on allowed lab CIDRs/domains and noninteractive approval | Medium | No active network tool runs before policy approval; disallowed/link-local/metadata/credential URLs fail closed; all entry points share the same check; monitor records decision; tests cover bypasses |
| Secure or disable public /invoke deployment | Current Render blueprint exposes model/tool capacity without auth or rate limits | agent_service.py, render.yaml, agent_registry.py, README.md, tests/ | Decide private demo versus authenticated public API | Medium | Unauthorized requests return 401/403; authorized callers are rate/concurrency limited; health response is minimal; secrets are never logged; local loopback flow remains easy |
| Preserve and commit a reproducible feature baseline | Current working tree contains major uncommitted scanner changes and untracked tests | Current modified files, tests/test_kali_url_attack.py | Review ownership and intended feature scope | Small | Intended files are reviewed, tests remain green, generated output stays excluded, and branch state is reproducible |

### P1 — Core Functionality

| Task | Why it matters | Files | Dependencies | Complexity | Acceptance criteria |
| --- | --- | --- | --- | --- | --- |
| Replace echo tool_agent with a safe, realistic dry-run tool agent | Current tool-abuse testing is not representative | targets/tool_using_agent/tool_agent.py, targets/_guardrails.py, tests/ | Define safe fake tools and approval model | Medium | Read-only fake tools have schemas and audit events; dangerous actions require approval and never execute; attacks produce meaningful outcomes |
| Make natural-language Kali status execute the real status check | Current assistant response is informational only | red_team_assistant.py, ai_red_team_cli.py, tests/test_red_team_assistant.py | Extract reusable status service | Small | “check Kali” runs the same validated status path and records structured monitor events |
| Define typed assessment/probe/result schemas | Nested dictionaries drift across scanners/reporters | scanner/, http_agent_attack.py, kali_*.py, enterprise_report.py | Choose dataclasses/Pydantic | Large | All producers validate a versioned schema; reporters consume one normalized form; invalid data fails clearly |
| Build a detector regression/evaluation corpus | Rule-only detectors can overclaim PASS or miss paraphrases | scanner/detectors.py, tests/fixtures/, tests/test_detectors.py | Labeled samples | Medium | Metrics for false positive/negative rates are generated; known benign reflection and disclosure cases are covered |
| Create run-scoped artifact storage | Fixed paths overwrite evidence and weaken handoff | assessment_monitor.py, enterprise_report.py, scanner/attack_runner.py | Define run ID/retention | Medium | Each assessment has a unique directory/manifest; latest pointer is optional; safe-share export is sanitized |
| Add end-to-end local assessment test | Unit tests do not prove the full user path | tests/, scripts/service_smoke.sh | Deterministic target, temporary report root | Medium | One command starts services, discovers/invokes a target, evaluates, and validates report schema without external network |

### P2 — Production Readiness

| Task | Why it matters | Files | Dependencies | Complexity | Acceptance criteria |
| --- | --- | --- | --- | --- | --- |
| Adopt pyproject and locked dependencies | Reproducible builds and tooling | pyproject.toml, lockfile, requirements.txt, scripts/bootstrap_dev.sh | Choose lock workflow | Medium | Clean Python 3.13 install is deterministic; hashes/versions are recorded; dependency audit passes |
| Add CI quality/security gates | Prevent regressions | .github/workflows/, pyproject.toml | Decide supported OS/Python matrix | Medium | Unit, compile, lint, type, secret scan, dependency audit, and diff checks run on PRs |
| Centralize validated configuration | Current env handling is distributed/inconsistent | new settings module, agent_service.py, model/assistant modules | Typed schema | Medium | Startup validates ports, URLs, timeouts, model names, and deployment mode with actionable errors |
| Add structured operational logging and metrics | Public/local failures are currently hard to diagnose | HTTP services, assessment_monitor.py | Logging/metrics choice | Medium | Redacted request IDs, latency, status, saturation, and dependency health are observable |
| Replace unbounded stdlib deployment server | Thread-per-request model is unsafe at scale | agent_service.py, render.yaml | Web framework/server choice | Large | Bounded workers, graceful shutdown, deadlines, auth middleware, and backpressure are tested |
| Harden report privacy and retention | Reports can contain target and prompt data | report modules, README.md | Retention policy | Medium | Restrictive permissions, configurable retention, URL sanitization, redaction tests, deletion runbook |
| Add opt-in integration suites | External dependencies are otherwise unverified | tests/integration/, scripts/ | Lab Ollama/weather/Kali fixtures | Large | Explicit flags run live contracts without production targets; failures are distinguishable from unit failures |
| Validate deployment and rollback | Render path is untested | render.yaml, docs/ | Safe staging environment | Medium | Authenticated staging smoke, health dependency check, rollback instructions, no public unauthenticated invoke |

### P3 — Enhancements

| Task | Why it matters | Files | Dependencies | Complexity | Acceptance criteria |
| --- | --- | --- | --- | --- | --- |
| Build a read-only dashboard | Improves learning/demo value | dashboard/, API/report reader | Secure API design | Large | Shows run history, findings, traces, and coverage without exposing secrets or starting scans implicitly |
| Expand target/plugin contract | Enables safe third-party target development | scanner/, docs/ | Isolation design | Large | Versioned manifest, sandbox/process boundary, capability declarations, validation command |
| Add attack packs and standards mapping | Portfolio and enterprise usability | attacks/, detectors, reports | Taxonomy design | Medium | Each finding maps to OWASP LLM/agent risks and has tests/remediation |
| Package supported document generators | Preserves portfolio outputs | scripts/, pyproject optional extras | Decide template ownership | Small | Scripts are tracked, dependencies declared, inputs documented, artifacts reproducible |
| Improve documentation | Reduces onboarding cost | docs/, README.md | Architecture decisions above | Medium | Threat model, API schemas, contribution guide, safe lab setup, deployment hardening, troubleshooting |

## 16. Recommended Next Task

Recommended task: implement one centralized authorization and scope-policy gate for every active Kali/URL assessment.

Why first: active scanning is the defining high-risk capability of this project, yet authorization currently exists only as prose. A shared policy gate reduces the chance of accidental public scanning, SSRF into sensitive networks, or a local-model intent escalating from interpretation to tools. It also creates the foundation for safe demos, CI tests, and later public UI work.

Likely files:

- New scope_policy.py for canonical URL/host validation and policy decisions.
- ai_red_team_cli.py for explicit acknowledgement flags and preflight errors.
- red_team_assistant.py for mandatory approval/policy enforcement after either parser.
- kali_url_attack.py and kali_agent_attack.py for defense-in-depth preflight checks.
- assessment_monitor.py for recorded authorization decisions without secrets.
- tests/test_scope_policy.py, tests/test_kali_url_attack.py, tests/test_red_team_assistant.py.
- README.md for the safe workflow.

Risks:

- DNS resolution/rebinding and IPv6 normalization are easy to implement incorrectly.
- Overly strict defaults can block the intended Kali tunnel workflow.
- Noninteractive CI and assistant commands need explicit, auditable authorization without prompting.
- Host aliases must be resolved consistently with SSH configuration.

Dependencies: decide the default allowed scope (recommended: loopback plus explicit configured lab destinations), the acknowledgement mechanism, and whether public targets are ever permitted.

Verification:

1. Unit-test URL canonicalization, schemes, ports, credentials, IPv4/IPv6, DNS answers, redirects, link-local, metadata, multicast, and private/public policy.
2. Mock SSH/tool entry points and assert they are never called on denial.
3. Test deterministic and local-model intent paths against the same policy.
4. Run the full validation script and loopback service smoke.
5. Perform an explicitly authorized loopback/Kali staging test only after review.

Acceptance criteria:

- Every active scan entry point invokes the same policy before network or subprocess activity.
- Default policy permits the intended loopback reverse-tunnel lab and denies unspecified public/internal targets.
- Public-target override requires explicit non-model-derived acknowledgement and a configured allowlist.
- Redirects and resolved addresses are revalidated.
- Denials are clear, nonzero, and recorded as policy events.
- No secret, SSH key path, or credential-bearing URL is emitted to reports.
- Existing 47 tests and new policy tests pass.

Do not implement this task until the allowed-scope product decision is confirmed.

## 17. Learning Guide

### Recommended reading order

1. README.md — product intent, supported workflows, and safety boundaries.
2. ai_red_team_cli.py:281-545 — all user-visible commands.
3. scanner/target_loader.py — how target enrollment works.
4. scanner/attack_runner.py:24-139 and 258-271 — payload loading, import, execution, and persistence.
5. scanner/detectors.py:168-338 — what PASS and FAIL actually mean.
6. One deterministic target: targets/tool_using_agent/tool_agent.py.
7. One guarded model target: targets/travel_agent/travel_agent.py.
8. targets/local_llm_agent/ollama_agent.py — provider client and failure behavior.
9. functional_agents/graphs.py and weather_tools.py — graph/tool integration.
10. agent_service.py and agent_lab_server.py — HTTP boundary.
11. agent_registry.py and http_agent_attack.py — discovery and dynamic probes.
12. kali_agent_attack.py, then kali_url_attack.py — remote transport and active testing.
13. red_team_assistant.py — orchestration after the primitives are understood.
14. assessment_monitor.py and enterprise_report.py — evidence model.
15. tests/ — executable specification and current limitations.

### Concepts to understand

- Python dynamic import and why explicit target enrollment is not sandboxing.
- Prompt injection versus prompt disclosure versus unsafe tool execution.
- Difference between a detector PASS and proof of security.
- Local Ollama HTTP generation and model-specific behavior.
- LangGraph state/node/edge execution.
- SSRF and why URL validation must consider DNS, redirects, and IP ranges.
- SSH reverse tunnels and loopback exposure.
- Authentication, authorization, rate limiting, and human approval as separate controls.
- Evidence provenance, redaction, retention, and coverage gaps.
- Fail-closed semantics for ERROR and UNPARSED results.

### Data movement

User command → CLI/intent → selected target/agent/URL → prompt generation → in-process/HTTP/SSH invocation → response normalization → rule detectors → result/probe/run → monitor and report artifacts.

### Design patterns

- Adapter: run_agent normalizes varied agents to one callable interface.
- Strategy-like detector composition: multiple detectors contribute findings.
- Explicit enrollment: REDTEAM_TARGET marker.
- Orchestrator: red_team_assistant.execute_intent().
- Compatibility wrapper: scanner/report_generator.py.
- Fallback: deterministic prompts/summaries when local models are unavailable.

### Five exercises

1. Add one harmless prompt line to an existing attack payload file, run a single-target scan, and trace the result into the per-target JSON and combined Markdown. Revert the exercise afterward.
2. Write a temporary test-only target with and without REDTEAM_TARGET = True and observe discover_targets().
3. Add a detector unit test for a paraphrased safe refusal and explain whether the current regex recognizes it.
4. Start agent_service.py with tool_agent, invoke /health, /metadata, and /invoke on loopback, and map each response field to its producer.
5. Mock _run_remote() in a new test and demonstrate that a timeout becomes UNPARSED/coverage error rather than PASS.

## 18. Questions and Unknowns

- Is public Render deployment an actual requirement, or should services remain private/loopback-only?
- Which exact domains, CIDRs, SSH aliases, and ports constitute authorized scan scope?
- Should public-target testing ever be permitted, and who records authorization?
- Is the ignored Dexter adapter intended to become a supported target or remain out of scope?
- Should agents/vulnerable_agent be enrolled as a deliberately vulnerable fixture or removed as legacy code?
- Is tool_agent intended to gain real safe tools, or remain a detector-control target?
- What report retention period and safe-sharing policy are required?
- Are assessment artifacts allowed to contain full prompts/responses in the intended environment?
- Which Ollama models and versions are officially supported and available in deployment?
- Who owns/provisions the external Ollama-compatible endpoint for Render, and what authentication does it require?
- Should OpenWeather be used only for geocoding, as currently implemented, or for forecast data too?
- What quality thresholds define a detector release: false-positive/negative rate, severity accuracy, or benchmark set?
- Should the untracked showcase/white-paper generators become supported project features?
- Is Windows support required? Current shell/SSH/Kali workflows assume Unix-like behavior.
- What is the intended licensing/distribution model? No license file was found.

Unverified during this audit: live Ollama/model behavior, weather-provider calls, live Kali/SSH reachability, real web target behavior, Render deployment, TLS/proxy configuration, dependency CVEs, load characteristics, and document generator execution.

## 19. AI Assistant Handoff

Project goal: provide an authorized, local-first AI agent red-team lab that discovers explicit Python targets, runs curated/adaptive/Kali-backed probes, evaluates responses, and produces auditable reports.

Tech stack: Python 3.13, unittest, standard-library HTTP/urllib/subprocess, Ollama, LangGraph, Open-Meteo/OpenWeather, SSH/Kali tools, JSON/JSONL/Markdown, Render blueprint.

Architecture: ai_red_team_cli.py and red_team_assistant.py orchestrate scanner, HTTP, and Kali paths. scanner/ discovers/imports run_agent targets and applies rule detectors. functional_agents/ supplies LangGraph tool-using targets. agent_service.py and agent_lab_server.py expose targets. report modules persist evidence.

Current state: 47 unit tests pass; full validation and loopback service smoke pass; six targets are discovered; deterministic smoke returns 6 PASS / 0 FAIL / 0 ERROR. The worktree has major pre-existing uncommitted Kali web-app changes plus untracked tests/artifact scripts. Do not overwrite or discard them.

Important constraints:

- Do not use this tool against systems without explicit authorization.
- Do not expose real secrets; test values in source are fake fixtures.
- Preserve Python 3.13 and the existing .venv bootstrap path.
- Treat ERROR/UNPARSED as coverage gaps, never as PASS.
- Keep local services on loopback unless authentication, authorization, quotas, and deployment hardening are implemented.
- Preserve unrelated dirty-worktree changes and generated artifacts.

Coding conventions: small Python modules, standard library where possible, unittest, explicit target marker, structured result dictionaries, redaction before persistence, CLI errors returned as nonzero status. There is no formatter/type configuration, so follow nearby style and run scripts/validate.sh plus git diff --check.

Security boundaries: SSH uses noninteractive key-based execution; reverse tunnels bind Kali loopback to Mac loopback. These are useful but insufficient. Active URL scope and public service authorization are not enforced.

Known issues: unauthenticated Render /invoke; no rate limits; no active-scan scope gate; model intent lacks strict post-parse policy; arbitrary URL/registry reachability; plaintext fixed-path reports; unpinned dependencies; no CI/lint/type/coverage; empty dashboard/docs; stub echo tool agent; partial NL Kali status; duplicate enterprise report write.

Current priority: P0 safety controls before expanding active scanning or public deployment.

Recommended next action: design and implement the centralized scan authorization/scope policy described in Section 16, after confirming allowed destinations and override rules.

Inspect first:

1. README.md
2. ai_red_team_cli.py
3. red_team_assistant.py
4. scanner/target_loader.py
5. scanner/attack_runner.py
6. scanner/detectors.py
7. kali_agent_attack.py
8. kali_url_attack.py
9. agent_service.py
10. tests/test_kali_url_attack.py and tests/test_red_team_assistant.py
