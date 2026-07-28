# Retesting

Retest classification uses the same stable fingerprints as report comparison.
It preserves the previous and current finding records and classifies evidence
as resolved, persistent, changed, or not retested.

```bash
redteam reports retest OLD_RUN_ID NEW_RUN_ID
redteam reports retest OLD_RUN_ID NEW_RUN_ID --json
```

A missing finding is not resolved when its category was skipped, unavailable,
not tested, errored, or timed out. Resolution requires relevant completed
coverage. Use the same target identity, scope, profile, and registered probes
where possible, then review evidence hashes and changed deployment context.
