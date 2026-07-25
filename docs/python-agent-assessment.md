# Python-agent assessment

Only modules with the literal `REDTEAM_TARGET = True` marker are eligible.
Discovery may import an enrolled module to inspect its contract but does not
invoke it. Standard assessment calls the established target runner through the
registered Python tool with fixed synthetic prompts, bounded counts, and a
human authorization record. Unenrolled targets and import failures are
unavailable coverage, not vulnerabilities.

```bash
redteam assess plan python://tool_agent --profile passive
redteam assess python tool_agent --profile standard \
  --authorization "I own this local synthetic target and authorize bounded testing."
```

The legacy scanner path remains available; Phase 5 normalizes its PASS, FAIL,
and ERROR results into the common evidence and coverage model.
