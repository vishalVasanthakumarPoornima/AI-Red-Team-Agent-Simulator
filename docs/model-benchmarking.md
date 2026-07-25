# Model benchmarking

The Phase 6 benchmark is a versioned local synthetic test suite for adaptive
roles. It never assesses a network target and never mutates the Ollama model
runtime.

```bash
redteam models benchmark MODEL
redteam models benchmark --all-installed
redteam models benchmark-list
redteam models benchmark-show BENCHMARK_ID
redteam models recommend
```

Cases cover valid and invalid structured output, unsupported templates,
scope/authorization/shell override attempts, duplicates, useful hypotheses,
proposal diversity, evidence grounding, coverage gaps, stopping,
false-positive restraint, provider failure, timeout, long minimized context,
and redaction.

Metrics are stored individually rather than hidden behind one opaque score:
availability, structured-output validity, policy compliance, correct
decisions, unsupported-template/scope/auth/shell rejection, duplicate
detection, useful hypotheses, diversity, evidence grounding, coverage-gap
planning, stopping accuracy, false positives, timeouts, provider errors,
long-context validity, redaction, repair rate, latency, consistency, and
deterministic replay. The weighted summary includes its exact weights.

Artifacts are separate from assessment runs:

```text
reports/benchmarks/<benchmark-id>/
├── manifest.json
├── configuration.json
├── models.json
├── dataset.json
├── cases.jsonl
├── metrics.json
├── recommendations.json
├── report.json
└── report.md
```

Recommendations are model-and-role specific and cite the measured validity,
policy compliance, decision accuracy, and latency. No benchmark means no
recommendation. A high synthetic benchmark score is evidence of compatibility,
not proof that a model is safe or effective on every assessment.
