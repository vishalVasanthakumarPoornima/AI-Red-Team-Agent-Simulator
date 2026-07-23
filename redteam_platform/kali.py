"""Authorized Kali readiness and deterministic tool registry."""

from __future__ import annotations

import json
import shlex

from kali_agent_attack import _run_remote
from redteam_platform.schemas import AuthorizationRecord
from redteam_platform.scope_policy import ScopePolicy
from redteam_platform.settings import Settings


REGISTERED_KALI_ACTIONS = {
    "nmap_service_light": {
        "binary": "nmap",
        "description": "Version-light TCP service identification on approved ports.",
    },
    "whatweb_passive": {
        "binary": "whatweb",
        "description": "Low-aggression web technology fingerprint.",
    },
    "nikto_bounded": {
        "binary": "nikto",
        "description": "Time-bounded noninteractive web configuration checks.",
    },
    "curl_headers": {
        "binary": "curl",
        "description": "HTTP status and response header collection.",
    },
    "sqlmap_lab_minimal": {
        "binary": "sqlmap",
        "description": "Explicit deep-lab-only, level 1/risk 1 bounded SQL validation.",
    },
}


def readiness(
    host: str,
    authorization: AuthorizationRecord,
    settings: Settings,
    *,
    identity_file: str | None = None,
    timeout: int = 8,
) -> dict:
    target = host if "://" in host else f"ssh://{host}"
    ScopePolicy(settings).require_record(target, authorization)
    script = """
set -u
printf '{"os":'
if [ -r /etc/os-release ]; then
  . /etc/os-release
  python3 -c 'import json,os; print(json.dumps(os.environ.get("PRETTY_NAME","unknown")), end="")'
else
  printf '"unknown"'
fi
printf ',"python":'
python3 -c 'import json,platform; print(json.dumps(platform.python_version()), end="")'
printf ',"tools":{'
first=1
for tool in nmap whatweb nikto curl sqlmap nuclei jq; do
  if [ "$first" -eq 0 ]; then printf ','; fi
  first=0
  if command -v "$tool" >/dev/null 2>&1; then
    version=$("$tool" --version 2>&1 | head -n 1 || true)
    TOOL="$tool" VERSION="$version" python3 -c 'import json,os; print(json.dumps(os.environ["TOOL"])+":"+json.dumps({"available":True,"version":os.environ["VERSION"]}), end="")'
  else
    TOOL="$tool" python3 -c 'import json,os; print(json.dumps(os.environ["TOOL"])+":"+json.dumps({"available":False,"version":None}), end="")'
  fi
done
printf '},"reverse_tunnel_supported":true}\n'
""".strip()
    result = _run_remote(
        host,
        timeout,
        script,
        identity_file=identity_file,
        command_timeout=30,
    )
    payload = None
    error = None
    if result["returncode"] == 0 and result["stdout"]:
        try:
            payload = json.loads(result["stdout"].splitlines()[-1])
        except json.JSONDecodeError as exc:
            error = f"Readiness response was not valid JSON: {exc}"
    else:
        error = result["stderr"] or "Kali readiness returned no data."
    return {
        "host": authorization.decision.normalized_target,
        "ready": bool(payload),
        "details": payload or {},
        "error": error,
        "registered_actions": REGISTERED_KALI_ACTIONS,
        "remote_returncode": result["returncode"],
    }


def build_registered_command(action: str, *, target: str, port: int | None = None) -> str:
    """Construct only deterministic allowlisted commands; models never supply shell text."""

    if action not in REGISTERED_KALI_ACTIONS:
        raise ValueError(f"Unknown Kali action: {action}")
    quoted_target = shlex.quote(target)
    if action == "nmap_service_light":
        if port is None or not 1 <= port <= 65535:
            raise ValueError("nmap_service_light requires an approved port.")
        return f"nmap -sV --version-light -p {port} {quoted_target}"
    if action == "whatweb_passive":
        return f"whatweb -a 1 {quoted_target}"
    if action == "nikto_bounded":
        return f"timeout 60s nikto -h {quoted_target} -nointeractive"
    if action == "curl_headers":
        return f"curl -sS -I --max-time 10 {quoted_target}"
    if action == "sqlmap_lab_minimal":
        return (
            f"timeout 90s sqlmap -u {quoted_target} --batch --level=1 --risk=1 "
            "--timeout=5 --retries=0"
        )
    raise ValueError(f"Command builder missing for action: {action}")

