# Enterprise reporting

Phase 7 turns completed Phase 1-6 run artifacts into a single canonical
Pydantic report and renders JSON, GitHub-compatible Markdown, self-contained
HTML, and optional PDF. The normalizer supports legacy enterprise, unified
target, Dexter, Kali-assisted, and adaptive artifact shapes.

Every completed assessment attempts to generate:

- `report.json`, `report.md`, and `report.html`
- `report.pdf` when ReportLab is installed
- `report_summary.json`, `findings_summary.json`, `coverage_summary.json`
- `remediation_plan.json` and `report_manifest.json`

Reporting errors are written to `reporting_errors.json` with a recovery
command. They do not alter findings, erase evidence, or change assessment
success. Rebuilding an older run preserves existing standard reports by using
`report_v7.*` unless overwrite is explicit.

The executive summary, qualitative risk rating, standards mappings, coverage,
and remediation ordering are deterministic. No model may invent findings,
coverage, or leadership conclusions.

```bash
redteam reports build RUN_ID
redteam reports build RUN_ID --all
redteam reports findings RUN_ID --severity high
redteam reports coverage RUN_ID
```

Reports document bounded evidence. They do not certify compliance and do not
prove the absence of vulnerabilities.
