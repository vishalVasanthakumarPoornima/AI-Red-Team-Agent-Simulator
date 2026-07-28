# Full Adaptive Demo Quick Reference

## Launch

```text
RUN_FULL_ADAPTIVE_DEMO.command
```

Then type:

```text
AUTHORIZE
```

## Required proof shown at the end

- New baseline run ID
- New adaptive run ID
- Kali checks greater than zero
- Adaptive mode `adaptive`
- Provider `ollama`
- Model calls greater than zero
- At least one round and probe
- Proposal decisions recorded
- Deterministic stop reason
- Adaptive manifest verified
- Demo package SHA-256 verified

## Primary files to present

1. `presentation/OPEN_ME_FIRST.html`
2. `presentation/ATTACK_WALKTHROUGH.html`
3. `presentation/DYNAMIC_RESULT.md`
4. `presentation/baseline_report_safe.md`
5. `presentation/adaptive_summary_safe.json`
6. `presentation/kali_activity_safe.json`

## Emergency fallback

`REPLAY_DEMO.command` remains separate and is always labeled replay. The strict live launcher never silently falls back.
