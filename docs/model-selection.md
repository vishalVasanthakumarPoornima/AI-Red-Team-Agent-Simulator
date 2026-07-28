# Adaptive model selection

Phase 6 uses only explicitly selected, locally discovered Ollama models.
Inventory distinguishes installed from currently running models. Selection
considers policy eligibility, installed/running state, model size,
quantization, context length, local memory evidence, completed benchmark
results, reliability, latency, and the operator's explicit role assignment.

```bash
redteam adaptive models
redteam adaptive models --live
redteam models recommend
```

`adaptive models` is passive by default. `--live` opts into bounded Phase 2
Ollama metadata discovery. Neither command pulls, loads, unloads, deletes, or
changes a model.

## Roles

- `planner`: chooses registered categories/templates from evidence-backed
  coverage gaps.
- `mutator`: proposes only allowed textual mutations.
- `summarizer`: summarizes minimized, sanitized assessment state.
- `reviewer`: ranks proposals or recommends stopping.

One model may fill multiple roles. Adaptive mode requires an explicitly
selected planner model. Comparative mode requires at least two distinct
explicit model selections. Fallback is disabled unless both a fallback model
and `--allow-fallback` are supplied.

```bash
redteam adaptive plan tool_agent \
  --adaptive-mode adaptive \
  --planner-model local-model:tag

redteam adaptive run tool_agent \
  --adaptive-mode comparative \
  --planner-model planner-model:tag \
  --reviewer-model reviewer-model:tag \
  --authorization "I own this local synthetic target and authorize bounded testing."
```

A missing or uninstalled model produces a clear unavailable result. A
deterministic fallback is used only when configuration explicitly permits it;
the fallback never expands the registered template set.

The Ollama provider is scoped through Phase 2 discovery, disables redirects,
bounds input/output sizes and timeouts, requests schema-constrained JSON, and
uses bounded retry/repair attempts. The provider sends `keep_alive: 0` and
never uses model-management endpoints.
