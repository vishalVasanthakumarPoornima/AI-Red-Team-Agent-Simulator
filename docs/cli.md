# CLI reference

## Phase 5 target and assessment commands

```text
redteam targets
redteam targets parse|resolve|show|capabilities|health TARGET
redteam assess plan TARGET
redteam assess run TARGET
redteam assess python|agent|ollama|host|web TARGET
```

`targets parse` is network-free. `assess plan` has no run side effects.
Every execution command requires `--authorization`; `--yes` is only a final
confirmation and cannot create authorization. Use `--json` globally or on the
command for a typed envelope. Resolution/scope denial exits 4, unavailable or
ambiguous targets exit 5, assessment failure exits 7, and interruption exits
130. Existing option-based Phase 3 commands and the specialized `dexter`
command group remain supported.

The supported executable is `redteam`; `python -m redteam_platform` is
equivalent. Running with no command opens the menu only when stdin and stdout
are terminals. A pipe, CI job, or `--non-interactive` execution prints help or
requires explicit options instead of prompting.

## Global options

```text
--config PATH        Select TOML configuration
--env-file PATH      Select environment file
--json               Machine-readable stdout only
--no-color           Disable ANSI output
--quiet              Suppress nonessential human output
--verbose            Show safe operational events
--debug              Show sanitized tracebacks
--non-interactive    Reject missing prompt input
--yes                Confirm eligible UI prompts; never authorization
--profile NAME       Attach profile metadata
--version            Print the application version
```

`NO_COLOR` is respected. `--quiet` and `--verbose` cannot be combined.

## Command hierarchy

```text
menu
inventory [refresh|show|summary]
models [list|running|installed|show]
agents [list|show|health]
services [list|show|listeners]
assess [start|plan|local-agent|python-target]
dexter [discover|list|show|health|plan|assess]
runs [list|show|events|artifacts]
reports [list|show|export]
kali [status|tools|check --live]
scope [show|validate|explain]
config [show|validate|paths]
doctor
help [getting-started|authorization|inventory|assessments]
version
```

Compatibility commands remain available: `inventory --json`, `models --json`,
`agents --json`, `services --json`, `kali-status --json`, `targets`,
`assess run`, `model benchmark`, and `api serve`.

## Passive and active behavior

Inventory, browsing, scope display, configuration, reports, and default
diagnostics do not execute attacks. Refresh can make bounded metadata requests
to configured policy-approved local endpoints. Docker is read-only and opt-in.
Kali SSH is never contacted unless `--live` is explicit.

`assess start` is active. It requires the exact kind, target, category/profile,
and a human authorization statement. The service normalizes and validates
scope before execution. Host/web expansion remains planned; Dexter is a
first-class Phase 4 target and is also accepted by `assess --kind dexter`.

## Dexter commands

```bash
redteam dexter discover
redteam dexter list --json
redteam dexter show DEXTER_ID
redteam dexter health DEXTER_ID
redteam dexter plan DEXTER_ID --profile standard
redteam dexter assess DEXTER_ID \
  --profile standard \
  --authorization "I own this local Dexter lab and authorize bounded testing." \
  --yes
```

`dexter plan` creates no run. An active non-interactive assessment requires the
exact ID, explicit profile, and human authorization statement; issuing that
complete command is its confirmation boundary. `--yes` is only an interactive
UI convenience and never supplies authorization. Deep-lab requires a real
interactive confirmation and ignores `--yes`. Use `--include-kali` only for a
configured authorized lab.

Dexter overrides are group options before the subcommand, for example:
`redteam dexter --endpoint http://127.0.0.1:8000 discover`.

## JSON contract

New non-interactive data commands use:

```json
{
  "schema_version": "1.0",
  "command": "agents.list",
  "success": true,
  "data": {},
  "warnings": [],
  "errors": []
}
```

JSON stdout contains no ANSI formatting or human progress. Errors use typed
objects. Event streaming is JSON Lines only with `runs events --json-lines`.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Success |
| 1 | General failure |
| 2 | Invalid CLI usage |
| 3 | Invalid configuration |
| 4 | Scope or authorization denied |
| 5 | Target or planned capability unavailable |
| 6 | Dependency unavailable |
| 7 | Assessment failed |
| 8 | Partial result in strict mode |
| 9 | Artifact or report failure |
| 130 | Interrupted |

Expected failures do not print tracebacks. `--debug` may print a sanitized
traceback for unexpected failures.

## Examples

```bash
redteam inventory refresh
redteam services list --loopback
redteam scope validate http://127.0.0.1:18080
redteam assess start \
  --kind python \
  --target tool_agent \
  --category prompt_disclosure \
  --authorization "I own this local synthetic target and authorize bounded testing."
redteam runs list --limit 10
redteam reports export RUN_ID --format markdown
redteam doctor --strict
```
