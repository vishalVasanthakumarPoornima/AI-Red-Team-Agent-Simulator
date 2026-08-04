# Project Freeze and Remaining Limitations

The feature-development phase is complete. Do not treat this file as a feature
backlog. The current verified state is recorded in
[`docs/FINAL_STATUS.md`](docs/FINAL_STATUS.md), and the recommended study path
is in [`docs/PROJECT_WALKTHROUGH.md`](docs/PROJECT_WALKTHROUGH.md).

Only the following known limitations remain:

- Full-repository Ruff and mypy checks contain documented legacy cleanup debt.
  The deterministic validation gate and checks for files changed in the final
  pass succeed.
- Live Ollama, Kali, SSH, Docker, and third-party service workflows require
  explicitly configured local lab dependencies and were not claimed as part of
  the dependency-free demo.
- The Docker CLI is installed on the validation host, but Docker Desktop was not
  running during the final pass, so an image build was not verified.
- `ai_red_team_cli.py` and other legacy entry points remain only for backward
  compatibility. New users should use the packaged `redteam` command.
- This repository intentionally has no frontend. The supported interfaces are
  the CLI, generated reports, and the optional authenticated loopback API.

Future activity should be limited to studying the code, recording the demo,
and correcting a verified defect if one is discovered. Do not expand active
scanning or weaken authorization and scope controls.
