# Configuration

`redteam_platform.settings.load_settings` applies configuration in this order:
TOML, repository `.env`, process environment, then explicit CLI/programmatic
overrides. Invalid values fail startup with field-specific messages. Secret
values are never included by `sanitized_settings`.

The checked-in examples use loopback-only, passive defaults:
`.env.example` and `config.example.toml`.

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
