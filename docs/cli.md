# CLI reference

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
scope before execution. Planned host/web/Dexter expansion is not launchable.

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
