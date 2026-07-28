# HTTP and OpenAI-compatible agent assessment

An HTTP URL alone is a web target. Classifying it as an AI agent requires
compatible inventory evidence, an explicit configured definition, or
`--kind agent`. Configuration defines invocation, health, metadata, OpenAPI,
request, and response fields. Passive assessment never sends POST.

OpenAI-compatible targets use an explicitly selected model and the configured
chat-completions route. Authentication is a non-secret reference mapped to an
environment-variable name; secret values are resolved only at request time and
redacted from artifacts.

```bash
redteam assess agent http://127.0.0.1:18080 --kind agent \
  --authorization "I own this local agent and authorize bounded testing."
redteam assess agent http://127.0.0.1:18081 --kind openai --model fixture-model \
  --authorization "I own this local endpoint and authorize bounded testing."
```
