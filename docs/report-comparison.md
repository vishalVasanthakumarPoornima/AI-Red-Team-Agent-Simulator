# Report comparison

Comparison matches findings by stable fingerprint and reports new, resolved,
persistent, and changed findings. Changes include severity, confidence, and
affected component. It also reports coverage, unavailable areas, probe counts,
duration, errors, and timeout deltas.

```bash
redteam reports compare OLD_RUN_ID NEW_RUN_ID
redteam reports compare OLD_RUN_ID NEW_RUN_ID --json
```

A comparison is only as strong as the comparable scope and completed probes.
Coverage regressions and newly unavailable categories remain visible instead
of being treated as improvement.
