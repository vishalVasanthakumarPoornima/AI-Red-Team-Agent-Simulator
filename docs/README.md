# Documentation

The repository keeps one concise documentation set for the supported CLI and
portfolio workflow. Start with the first three files; use the remaining pages
when studying a specific subsystem.

| Document | Use it for |
| --- | --- |
| [`DEMO_GUIDE.md`](DEMO_GUIDE.md) | Recording the deterministic end-to-end demonstration |
| [`PROJECT_WALKTHROUGH.md`](PROJECT_WALKTHROUGH.md) | Studying architecture, data flow, security boundaries, and interview questions |
| [`FINAL_STATUS.md`](FINAL_STATUS.md) | Confirmed test results, limitations, environment requirements, and study order |
| [`cli.md`](cli.md) | Complete command hierarchy, options, JSON contract, and exit codes |
| [`configuration.md`](configuration.md) | TOML and environment settings for core and optional integrations |
| [`SECURITY.md`](SECURITY.md) | Threat model and defensive controls |
| [`scope-and-authorization.md`](scope-and-authorization.md) | Target policy and human-authorization rules |
| [`assessments.md`](assessments.md) | Deterministic planner/executor behavior and coverage semantics |
| [`adaptive-assessment.md`](adaptive-assessment.md) | Bounded local-model proposal workflow |
| [`reporting.md`](reporting.md) | Canonical reports, formats, and integrity behavior |
| [`dexter-assessment.md`](dexter-assessment.md) | Optional Dexter discovery and assessment workflow |

The root [`README.md`](../README.md) remains the authoritative clean-install
and quick-start guide. Command help is generated from the installed command
tree, so use `redteam help COMMAND` for the most precise option-level usage.

Historical audit snapshots, phase logs, duplicated setup pages, narrow command
fragments, and generated presentation binaries are intentionally not retained.
Git history preserves them if provenance is ever needed.
