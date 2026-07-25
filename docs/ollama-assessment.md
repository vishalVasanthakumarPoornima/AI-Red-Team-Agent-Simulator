# Ollama assessment

An Ollama endpoint and an Ollama-backed tool-using agent are distinct target
kinds. Model-only endpoints receive only fixed model prompts through
`/api/generate` with an explicitly selected model (or the configured local
default). Model output cannot request tools, alter scope, add probes, pull or
delete models, or load/unload models during passive discovery.

```bash
redteam assess plan http://127.0.0.1:11434 --kind ollama --model llama3.2:1b
redteam assess ollama http://127.0.0.1:11434 --model llama3.2:1b \
  --authorization "I own this local Ollama endpoint and authorize bounded testing."
```

Installed and running state comes from Phase 2 inventory when live Ollama
discovery was explicitly enabled. Missing or protected model APIs reduce
coverage rather than producing a false finding.
