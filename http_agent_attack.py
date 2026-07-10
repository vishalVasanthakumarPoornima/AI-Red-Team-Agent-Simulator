"""Attack compatible HTTP agent services discovered on the local machine."""

from datetime import datetime, timezone
from pathlib import Path
import json
import urllib.error
import urllib.request

from kali_agent_attack import DEFAULT_PROBES
from scanner.attack_runner import REPORTS_DIR, status_counts
from scanner.detectors import evaluate_response


DEFAULT_REPORT_PATH = REPORTS_DIR / "http_agent_scan.json"


def _post_json(url, payload, timeout):
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_body = response.read().decode("utf-8", errors="replace")
        return {
            "url": url,
            "returncode": 0,
            "http_status": response.status,
            "stdout": response_body,
            "stderr": "",
        }
    except urllib.error.HTTPError as exc:
        return {
            "url": url,
            "returncode": 1,
            "http_status": exc.code,
            "stdout": exc.read().decode("utf-8", errors="replace"),
            "stderr": str(exc),
        }
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        return {
            "url": url,
            "returncode": 1,
            "http_status": None,
            "stdout": "",
            "stderr": str(exc),
        }


def _normalize_http_response(agent, target_name, attack, prompt, http_result):
    parsed = None
    result = None
    parse_error = None

    if http_result["returncode"] != 0:
        parse_error = http_result["stderr"] or f"HTTP status {http_result['http_status']}."
    elif not http_result["stdout"]:
        parse_error = "HTTP service returned an empty response."
    else:
        try:
            parsed = json.loads(http_result["stdout"])
        except json.JSONDecodeError as exc:
            parse_error = str(exc)

    if isinstance(parsed, dict) and "status" in parsed:
        result = parsed
    elif isinstance(parsed, dict) and "response" in parsed:
        result = {
            "target": target_name,
            "attack": attack,
            "prompt": prompt,
            "response": parsed["response"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **evaluate_response(prompt, parsed["response"], attack),
        }
    elif parsed is not None and parse_error is None:
        parse_error = "JSON response did not contain status or response."

    return {
        "agent": agent.get("name"),
        "agent_kind": agent.get("kind"),
        "target": target_name,
        "attack": attack,
        "prompt": prompt,
        "http": http_result,
        "raw_response": parsed,
        "result": result,
        "parse_error": parse_error,
    }


def _agent_targets(agent):
    targets = agent.get("targets") or []
    if targets:
        return targets
    return [agent.get("name") or agent.get("base_url") or "unknown_agent"]


def _summarize(probes):
    results = [
        probe["result"]
        for probe in probes
        if isinstance(probe.get("result"), dict) and "status" in probe["result"]
    ]
    counts = status_counts(results) if results else {"PASS": 0, "FAIL": 0, "ERROR": 0}
    return {
        "tests": len(results),
        "pass": counts["PASS"],
        "fail": counts["FAIL"],
        "error": counts["ERROR"],
        "unparsed": sum(1 for probe in probes if probe.get("parse_error")),
    }


def run_http_agent_attack(agents, timeout=30, report_path=DEFAULT_REPORT_PATH):
    probes = []
    for agent in agents:
        if agent.get("status") != "up":
            continue
        invoke_url = agent.get("invoke_url")
        if not invoke_url:
            continue
        targets = _agent_targets(agent)
        requires_target = bool(agent.get("targets"))
        for target_name in targets:
            for attack, prompt in DEFAULT_PROBES:
                payload = {"attack": attack, "prompt": prompt}
                if requires_target:
                    payload["target"] = target_name
                http_result = _post_json(invoke_url, payload, timeout)
                probes.append(
                    _normalize_http_response(
                        agent,
                        target_name,
                        attack,
                        prompt,
                        http_result,
                    )
                )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "agents": agents,
        "probes": probes,
        "summary": _summarize(probes),
    }

    if report_path:
        path = Path(report_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        report["report_path"] = str(path)
    return report
