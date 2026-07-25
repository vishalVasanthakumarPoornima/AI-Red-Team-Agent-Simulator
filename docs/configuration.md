# Configuration

## Phase 5 target and budget settings

`generic_targets`, `http_agent_definitions`, and
`openai_compatible_endpoints` declare loopback/private-lab targets without
embedding credentials. `authentication_references` maps a safe reference name
to an environment-variable name. The secret value is read only at request
time.

Host/web bounds are controlled by `approved_host_ports`,
`host_timeout_seconds`, `web_path_allowlist`, `maximum_redirects`,
`maximum_response_bytes`, `assessment_maximum_requests`,
`assessment_maximum_duration_seconds`, `assessment_maximum_concurrency`,
`tls_verify`, and `tls_minimum_version`. `profile_budgets` provides hard caps
for passive, standard, and deep-lab. Kali and nuclei names must be explicitly
allowlisted. See `config.example.toml` for loopback-only examples.

`redteam_platform.settings.load_settings` applies configuration in this order:
TOML, the selected environment file, process environment, then explicit
CLI/programmatic overrides. `--config PATH` and `--env-file PATH` select the
first two layers. Invalid values fail startup with field-specific messages.
Secret values are never included by `sanitized_settings`.

The checked-in examples use loopback-only, passive defaults:
`.env.example` and `config.example.toml`.

Use the offline inspection commands:

```bash
redteam config show
redteam config validate
redteam config paths
```

`config show` redacts secret values and SSH key paths. `config validate` does
not contact integrations. `config paths` reports existence and writability for
the selected config/environment files, inventory cache, reports, and log path.

## Phase 2 inventory settings

| Environment variable | TOML field | Default | Purpose |
| --- | --- | --- | --- |
| `REDTEAM_OLLAMA_ENDPOINTS` | `ollama_endpoints` | `http://127.0.0.1:11434` | Comma-separated configured Ollama base URLs. Credentials are rejected. |
| `REDTEAM_OLLAMA_DISCOVERY_TIMEOUT` | `ollama_discovery_timeout` | `1.5` | Per-request Ollama metadata timeout in seconds. |
| `REDTEAM_OLLAMA_LIVE_CHECK` | `ollama_live_check` | `false` | Enables bounded live Ollama metadata checks. Prefer the CLI `--live` opt-in. |
| `REDTEAM_METADATA_RESPONSE_SIZE` | `metadata_response_size` | `2000000` | Maximum bytes accepted from one metadata response. |
| `REDTEAM_LISTENER_DISCOVERY_METHOD` | `listener_discovery_method` | `auto` | `auto`, `psutil`, or native (`lsof`/`ss`). |
| `REDTEAM_LISTENER_CACHE_TTL_SECONDS` | `listener_cache_ttl_seconds` | `30` | Reserved TTL for independent listener refreshes. |
| `REDTEAM_INCLUDE_UDP` | `include_udp` | `false` | Include passive UDP socket inventory. |
| `REDTEAM_INCLUDE_DOCKER` | `include_docker` | `false` | Include read-only Docker inventory by default. |
| `REDTEAM_INCLUDE_STOPPED_CONTAINERS` | `include_stopped_containers` | `false` | Use `docker ps --all` when Docker inventory is requested. |
| `REDTEAM_DOCKER_TIMEOUT` | `docker_timeout` | `5` | Docker metadata command timeout in seconds. |
| `REDTEAM_INCLUDE_KALI_READINESS` | `include_kali_readiness` | `false` | Include Kali configuration/readiness records. |
| `REDTEAM_KALI_LIVE_CHECK` | `kali_live_check` | `false` | Enables the fixed SSH readiness check. Prefer the CLI `--live` opt-in. |
| `REDTEAM_KALI_READINESS_TIMEOUT` | `kali_readiness_timeout` | `8` | SSH readiness connection timeout in seconds. |
| `REDTEAM_HTTP_METADATA_ROUTES` | `http_metadata_routes` | `/health,/metadata,/targets,/openapi.json,/v1/models` | Comma-separated GET-only metadata paths. |
| `REDTEAM_KNOWN_LOCAL_SERVICE_PORTS` | `known_local_service_ports` | `18080,18101,18102,8000,8080,5000,5001` | Known project ports considered only when already listening. |
| `REDTEAM_INVENTORY_CACHE` | `inventory_cache` | `reports/cache/inventory.json` | Standalone typed inventory cache location. |
| `REDTEAM_INVENTORY_CACHE_TTL_SECONDS` | `inventory_cache_ttl_seconds` | `60` | Complete snapshot cache TTL in seconds. |
| `REDTEAM_PASSIVE_ONLY` | `passive_only` | `true` | Records the passive-only inventory safety mode. |

## Related Phase 1 scope settings

| Environment variable | Purpose |
| --- | --- |
| `REDTEAM_ALLOWED_CIDRS` | Lab networks allowed by policy; defaults to IPv4/IPv6 loopback only. |
| `REDTEAM_ALLOWED_DOMAINS` | Exact or suffix domains explicitly allowed for local/lab use. |
| `REDTEAM_CONFIGURED_AGENT_ENDPOINTS` | Explicit compatible-service candidates. |
| `REDTEAM_ALLOWED_KALI_ALIASES` | Exact SSH aliases allowed for Kali readiness or assessment. |
| `KALI_SSH_HOST` | Configured exact Kali alias or lab host. |
| `KALI_SSH_KEY` | Optional authorized lab key path; the path is redacted from persisted settings. |
| `REDTEAM_ALLOW_PUBLIC` | Public-target enablement; remains `false` by default and does not bypass authorization. |

URLs must use HTTP or HTTPS, contain no credentials, and have valid hosts and
ports. Metadata routes must be absolute paths without a URL, query, fragment,
or traversal. Known ports must be between 1 and 65535. Timeouts and cache TTLs
must be positive and within the bounds enforced by `Settings`.

`OLLAMA_URL`, `OLLAMA_MODEL`, and `OLLAMA_TIMEOUT_SECONDS` are legacy
assessment-agent settings. They are distinct from the passive inventory
settings above.

## Dexter settings

The `[redteam.dexter]` table defines the primary deployment. The settings
system can also represent additional typed `dexter_deployments`.

| Environment variable | TOML field | Purpose |
| --- | --- | --- |
| `DEXTER_NAME` | `name` | Deployment display name. |
| `DEXTER_API_ENDPOINT` | `api_endpoint` | Main HTTP(S) base URL. |
| `DEXTER_HEALTH_PATH` | `health_path` | GET-only readiness route. |
| `DEXTER_CHAT_PATH` | `chat_path` | Registered invocation route. |
| `DEXTER_METADATA_PATH` | `metadata_path` | Passive metadata route. |
| `DEXTER_OPENAPI_PATH` | `openapi_path` | Passive OpenAPI route. |
| `DEXTER_AUTHENTICATION_MODE` | `authentication_mode` | Declared authentication boundary. |
| `DEXTER_AUTHENTICATION_REFERENCE` | `authentication_reference` | Non-secret reference name only. |
| `DEXTER_OLLAMA_ENDPOINT` | `ollama_endpoint` | Associated local Ollama base URL. |
| `DEXTER_EXPECTED_MODEL` | `expected_model` | Expected installed/loaded model. |
| `DEXTER_TOOL_ENDPOINTS` | `tool_endpoints` | Comma-separated local tool service URLs. |
| `DEXTER_MEMORY_ENDPOINT` | `memory_endpoint` | Optional memory service URL. |
| `DEXTER_VECTOR_ENDPOINT` | `vector_endpoint` | Optional vector database URL. |
| `DEXTER_RETRIEVAL_ENDPOINT` | `retrieval_endpoint` | Optional retrieval URL. |
| `DEXTER_VOICE_ENDPOINTS` | `voice_endpoints` | Optional comma-separated voice URLs. |
| `DEXTER_DOCKER_NAMES` | `docker_names` | Expected local container names/images. |
| `DEXTER_DOCKER_LABELS` | `docker_labels` | Expected safe `key=value` labels. |
| `DEXTER_EXPECTED_PORTS` | `expected_ports` | Ports used for deterministic correlation. |
| `DEXTER_ALLOWED_PROFILES` | `allowed_profiles` | Allowed Phase 4 profiles. |
| `DEXTER_DISPOSABLE_MEMORY_NAMESPACE` | `disposable_memory_namespace` | Permits synthetic writes only in a disposable namespace. |
| `DEXTER_REQUIRES_KALI_TUNNEL` | `requires_kali_tunnel` | Requires an owned reverse tunnel for optional Kali. |
| `DEXTER_KALI_REMOTE_PORT` | `kali_remote_port` | Fixed remote loopback tunnel port. |

All endpoint URLs reject embedded credentials. Paths reject queries and
fragments. The authentication reference is persisted, but the referenced
secret is not. TOML is overridden by `.env`, then process environment, then
explicit programmatic or Dexter group CLI overrides.
