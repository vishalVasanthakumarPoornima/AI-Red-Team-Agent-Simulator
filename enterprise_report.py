"""Enterprise-style reporting for natural-language red-team assessments."""

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import json
import re

from scanner.attack_runner import REPORTS_DIR, fenced_text, status_counts, truncate_text
from scanner.detectors import redact_configured_secrets


DEFAULT_REPORT_PATH = REPORTS_DIR / "enterprise_red_team_report.md"
DEFAULT_JSON_PATH = REPORTS_DIR / "enterprise_red_team_report.json"
SEVERITY_RANK = {
    "Informational": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
    "Error": 3,
}
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def _iter_results(assessment):
    for run_name, run in assessment.get("runs", {}).items():
        for result in run.get("results", []):
            yield run_name, result
        for probe in run.get("probes", []):
            result = probe.get("result")
            if isinstance(result, dict):
                yield run_name, result
            elif probe.get("parse_error"):
                yield run_name, {
                    "target": probe.get("target") or probe.get("agent") or "unknown",
                    "attack": probe.get("attack") or "unknown",
                    "status": "ERROR",
                    "severity": "Error",
                    "reason": probe.get("parse_error"),
                    "prompt": probe.get("prompt", ""),
                    "response": "",
                    "detectors": ["unparsed_response"],
                    "evidence": [probe.get("parse_error")],
                }


def _all_results(assessment):
    return list(_iter_results(assessment))


def _status_summary(results):
    plain_results = [result for _, result in results if "status" in result]
    counts = status_counts(plain_results) if plain_results else {"PASS": 0, "FAIL": 0, "ERROR": 0}
    return {
        "tests": len(plain_results),
        "pass": counts["PASS"],
        "fail": counts["FAIL"],
        "error": counts["ERROR"],
    }


def _finding_rows(results):
    rows = []
    for index, (run_name, result) in enumerate(results, start=1):
        status = result.get("status")
        if status not in {"FAIL", "ERROR"}:
            continue
        severity = result.get("severity", "Error" if status == "ERROR" else "High")
        rows.append(
            {
                "id": f"AI-RT-{index:03d}",
                "run": run_name,
                "target": _display_target(result.get("target", "unknown")),
                "attack": result.get("attack", "unknown"),
                "status": status,
                "severity": severity,
                "reason": result.get("reason", "No reason provided."),
                "evidence": result.get("evidence", []),
                "prompt": result.get("prompt", ""),
                "response": result.get("response", ""),
            }
        )
    return sorted(rows, key=lambda row: SEVERITY_RANK.get(row["severity"], 0), reverse=True)


def _dynamic_summary(assessment):
    recon_count = 0
    generated_count = 0
    for run in assessment.get("runs", {}).values():
        recon_count += len(run.get("reconnaissance", []) or [])
        for generated in (run.get("generated_payloads", {}) or {}).values():
            generated_count += len(generated.get("payloads", []) or [])
    return {"reconnaissance": recon_count, "generated_payloads": generated_count}


def _escape_table(value):
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def _safe_excerpt(value, limit=240):
    text = ANSI_ESCAPE_RE.sub("", redact_configured_secrets(value))
    return truncate_text(text, limit=limit)


def _display_target(value):
    text = str(value or "unknown")
    parsed = urlparse(text)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    return text


def _tool_status(returncode):
    if returncode is None:
        return "unknown"
    return "ok" if returncode == 0 else "error"


def _remediation_for(finding):
    reason = str(finding.get("reason", "")).lower()
    if finding.get("status") == "ERROR" and (
        "timeout" in reason or "timed out" in reason or "exited 28" in reason or "exit 28" in reason
    ):
        return (
            "Treat this as a coverage gap: check Ollama/model health, increase the configured timeout "
            "only if needed, and rerun the affected probe."
        )
    if finding.get("status") == "ERROR":
        return "Fix service reliability or parser compatibility so failures cannot hide security findings."
    attack = str(finding.get("attack", "")).lower()
    if "sensitive_data_exposure" in attack:
        return (
            "Require local session authorization for task, chat, and memory APIs; minimize returned history; "
            "and redact sensitive fields from list endpoints."
        )
    if "tool_policy_exposure" in attack:
        return (
            "Restrict tool-policy endpoints to authenticated local sessions and avoid exposing dangerous command "
            "entries unless the caller has an explicit admin/debug role."
        )
    if "json_reflection" in attack:
        return (
            "Keep JSON responses escaped at every UI render point, validate reflected fields, and add browser tests "
            "that confirm payloads are rendered as text rather than HTML."
        )
    if "secret" in attack:
        return "Move secrets out of prompts and tools, enforce secret redaction, and add output filtering tests."
    if "prompt" in attack:
        return "Strengthen prompt isolation, refuse hidden-instruction disclosure, and regression-test known bypass prompts."
    if "tool" in attack:
        return "Add tool authorization checks, dry-run guards, scoped permissions, and audit logs before tool execution."
    return "Review the affected agent policy, add a targeted guardrail, and rerun the red-team suite."


def _observability_lines(assessment):
    monitoring = assessment.get("monitoring") or {}
    lines = [
        "## Assessment Observability",
        "",
        "- Observable trace coverage: interpreted intent, service discovery, generated probes, HTTP calls, Kali commands, return codes, and result statuses.",
        "- Thought visibility: this report records observable planning and tool use, not hidden model chain-of-thought.",
    ]
    if monitoring:
        if monitoring.get("timeline_markdown"):
            lines.append(f"- Timeline: `{monitoring['timeline_markdown']}`")
        if monitoring.get("events_jsonl"):
            lines.append(f"- Event stream: `{monitoring['events_jsonl']}`")
        if monitoring.get("events_recorded") is not None:
            lines.append(f"- Events recorded: {monitoring['events_recorded']}")
    else:
        lines.append("- No assessment monitor artifact was attached to this assessment.")
    lines.append("")
    return lines


def _kali_scope_lines(assessment):
    lines = ["", "### Kali Lab Assessment", ""]
    found = False
    for run_name, run in assessment.get("runs", {}).items():
        if run_name == "kali_agent_scan":
            found = True
            lines.append(f"- Kali host: `{run.get('kali_host', 'unknown')}`")
            lines.append(f"- Base URL from Kali: `{run.get('base_url_on_kali', 'unknown')}`")
            targets = ", ".join(f"`{target}`" for target in run.get("targets", []) or [])
            lines.append(f"- Exposed lab targets: {targets or 'none'}")
        elif run_name.startswith("kali_url_scan"):
            found = True
            tunnel = run.get("reverse_tunnel") or {}
            lines.append(f"- Kali host: `{run.get('kali_host', 'unknown')}`")
            lines.append(f"- Original target URL: `{run.get('original_target_url', run.get('target_url', 'unknown'))}`")
            lines.append(f"- Effective URL from Kali: `{run.get('target_url', 'unknown')}`")
            lines.append(f"- Reverse tunnel: `{bool(tunnel.get('enabled'))}`")
            if tunnel.get("enabled"):
                lines.append(
                    f"- Tunnel mapping: Kali `127.0.0.1:{tunnel.get('remote_port')}` -> "
                    f"local `127.0.0.1:{tunnel.get('local_port')}`"
                )
        else:
            continue
    if not found:
        lines.append("- No Kali-backed assessment run was included.")
    return lines


def _dynamic_generation_lines(assessment):
    lines = ["## Dynamic Probe Generation", ""]
    found = False
    for run_name, run in assessment.get("runs", {}).items():
        generated_payloads = run.get("generated_payloads") or {}
        for target_name, generated in generated_payloads.items():
            found = True
            lines.extend(
                [
                    f"### {target_name}",
                    "",
                    f"- Run: `{run_name}`",
                    f"- Generator: `{generated.get('generator', 'unknown')}`",
                    f"- Source agent: `{generated.get('agent', 'unknown')}`",
                    f"- Context excerpt: {_safe_excerpt(generated.get('context_excerpt', ''), limit=300)}",
                    "",
                    "| Attack | Prompt excerpt |",
                    "| --- | --- |",
                ]
            )
            for payload in generated.get("payloads", []):
                lines.append(
                    f"| {_escape_table(payload.get('attack'))} | "
                    f"{_escape_table(_safe_excerpt(payload.get('prompt'), limit=260))} |"
                )
            lines.append("")
    if not found:
        lines.append("No dynamic probes were generated in this assessment.")
        lines.append("")
    return lines


def _http_trace_lines(run_name, run):
    lines = [f"### {run_name}", ""]
    probes = []
    for probe in run.get("reconnaissance", []) or []:
        probes.append(("recon", probe))
    for probe in run.get("probes", []) or []:
        probes.append(("attack", probe))

    if not probes:
        lines.append("No HTTP probes were recorded.")
        lines.append("")
        return lines

    lines.extend(
        [
            "| Type | Agent | Target | Attack | HTTP | Result | Notes |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    row_limit = 40
    for probe_type, probe in probes[:row_limit]:
        result = probe.get("result") or {}
        http = probe.get("http") or {}
        http_status = http.get("http_status") or "n/a"
        result_status = result.get("status") or ("ERROR" if probe.get("parse_error") else "UNPARSED")
        notes = probe.get("parse_error") or result.get("reason") or ""
        lines.append(
            f"| {probe_type} | {_escape_table(probe.get('agent'))} | "
            f"{_escape_table(_display_target(probe.get('target')))} | {_escape_table(probe.get('attack'))} | "
            f"{_escape_table(http_status)} | {_escape_table(result_status)} | "
            f"{_escape_table(_safe_excerpt(notes, limit=180))} |"
        )
    if len(probes) > row_limit:
        lines.append(f"| ... | ... | ... | ... | ... | ... | {len(probes) - row_limit} additional probes omitted from this table. |")
    lines.append("")
    return lines


def _kali_trace_lines(run_name, run):
    lines = [f"### {run_name}", ""]
    has_rows = False
    web_recon = run.get("web_recon") or {}
    if web_recon:
        has_rows = True
        lines.extend(
            [
                "| Tool | Command | Return Code | Status | Output excerpt |",
                "| --- | --- | ---: | --- | --- |",
            ]
        )
        for tool_name, result in web_recon.items():
            returncode = result.get("returncode")
            output = result.get("stdout") or result.get("stderr") or ""
            lines.append(
                f"| {_escape_table(tool_name)} | `{_escape_table(_safe_excerpt(result.get('command'), limit=180))}` | "
                f"{returncode} | {_tool_status(returncode)} | "
                f"{_escape_table(_safe_excerpt(output, limit=220))} |"
            )
        lines.append("")

    endpoint_checks = run.get("endpoint_checks")
    if endpoint_checks:
        has_rows = True
        returncode = endpoint_checks.get("returncode")
        lines.extend(
            [
                "| Tool | Command | Return Code | Status | Output excerpt |",
                "| --- | --- | ---: | --- | --- |",
                (
                    f"| curl endpoint sweep | `{_escape_table(_safe_excerpt(endpoint_checks.get('command'), limit=180))}` | "
                    f"{returncode} | {_tool_status(returncode)} | "
                    f"{_escape_table(_safe_excerpt(endpoint_checks.get('stdout') or endpoint_checks.get('stderr'), limit=260))} |"
                ),
                "",
            ]
        )

    probes = run.get("probes") or []
    if probes:
        has_rows = True
        lines.extend(
            [
                "| Target | Attack | Remote Return Code | Result | Notes |",
                "| --- | --- | ---: | --- | --- |",
            ]
        )
        for probe in probes[:40]:
            result = probe.get("result") or {}
            remote = probe.get("remote") or {}
            notes = probe.get("parse_error") or result.get("reason") or ""
            lines.append(
                f"| {_escape_table(_display_target(probe.get('target')))} | {_escape_table(probe.get('attack'))} | "
                f"{remote.get('returncode')} | {_escape_table(result.get('status') or 'UNPARSED')} | "
                f"{_escape_table(_safe_excerpt(notes, limit=180))} |"
            )
        if len(probes) > 40:
            lines.append(f"| ... | ... | ... | ... | {len(probes) - 40} additional probes omitted from this table. |")
        lines.append("")

    if not has_rows:
        lines.append("No Kali command trace was recorded.")
        lines.append("")
    return lines


def _tool_execution_trace_lines(assessment):
    lines = ["## Tool Execution Trace", ""]
    found = False
    for run_name, run in assessment.get("runs", {}).items():
        if run_name == "http_agent_scan":
            found = True
            lines.extend(_http_trace_lines(run_name, run))
        elif run_name == "kali_agent_scan" or run_name.startswith("kali_url_scan"):
            found = True
            lines.extend(_kali_trace_lines(run_name, run))
    if not found:
        lines.append("No HTTP service or Kali tool execution trace was recorded.")
        lines.append("")
    return lines


def _reliability_lines(results):
    errors = [
        (run_name, result)
        for run_name, result in results
        if result.get("status") == "ERROR"
    ]
    lines = ["## Reliability Notes", ""]
    if not errors:
        lines.append("No execution or parser errors were recorded.")
        lines.append("")
        return lines

    lines.append(
        "Execution and parser errors are coverage gaps, not confirmed exploitability. "
        "They should be rerun after runtime health checks because they can hide missed findings."
    )
    lines.extend(
        [
            "",
            "| Run | Target | Attack | Reason | Suggested action |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for run_name, result in errors:
        pseudo_finding = {
            "status": "ERROR",
            "attack": result.get("attack"),
            "reason": result.get("reason", ""),
        }
        lines.append(
            f"| {_escape_table(run_name)} | {_escape_table(_display_target(result.get('target')))} | "
            f"{_escape_table(result.get('attack'))} | "
            f"{_escape_table(_safe_excerpt(result.get('reason'), limit=220))} | "
            f"{_escape_table(_remediation_for(pseudo_finding))} |"
        )
    lines.append("")
    return lines


def build_enterprise_report(assessment):
    generated_at = datetime.now(timezone.utc).isoformat()
    results = _all_results(assessment)
    summary = _status_summary(results)
    findings = _finding_rows(results)
    active_agents = assessment.get("active_agents", [])
    targets = assessment.get("targets", [])
    run_names = list(assessment.get("runs", {}))
    dynamic_summary = _dynamic_summary(assessment)

    lines = [
        "# Enterprise AI Red Team Assessment",
        "",
        f"Generated: {generated_at}",
        f"Assessment request: {assessment.get('request', 'Not provided')}",
        "",
        "## Executive Summary",
        "",
        f"- Total test cases evaluated: {summary['tests']}",
        f"- Confirmed security failures: {summary['fail']}",
        f"- Runtime or parser coverage errors: {summary['error']}",
        f"- Active local services discovered: {len(active_agents)}",
        f"- Repository targets in scope: {len(targets)}",
        f"- Assessment runs executed: {', '.join(run_names) if run_names else 'none'}",
        f"- Reconnaissance probes completed: {dynamic_summary['reconnaissance']}",
        f"- Dynamic probes generated: {dynamic_summary['generated_payloads']}",
        "",
    ]

    confirmed_findings = [finding for finding in findings if finding["status"] == "FAIL"]
    if confirmed_findings:
        highest = confirmed_findings[0]["severity"]
        lines.append(
            f"Overall result: findings require remediation. Highest observed severity: {highest}."
        )
    elif findings:
        highest = findings[0]["severity"]
        lines.append(
            "Overall result: no confirmed vulnerabilities were detected, but runtime or parser "
            f"coverage errors require rerun. Highest coverage severity: {highest}."
        )
    else:
        lines.append(
            "Overall result: no confirmed vulnerabilities were detected in the bounded tests that completed. "
            "This is not a guarantee of security; it is evidence from the configured assessment scope."
        )

    lines.extend(
        [
            "",
            "## Scope",
            "",
            "### Repository Targets",
            "",
        ]
    )
    if targets:
        for target in targets:
            lines.append(f"- `{target.get('name')}`: `{target.get('path')}`")
    else:
        lines.append("- No repository targets were included.")

    lines.extend(["", "### Active Local Agents", ""])
    if active_agents:
        for agent in active_agents:
            targets_text = ", ".join(agent.get("targets") or [])
            suffix = f" targets: {targets_text}" if targets_text else ""
            lines.append(f"- `{agent.get('name')}` ({agent.get('kind')}): {agent.get('base_url')}{suffix}")
    else:
        lines.append("- No active compatible local services were discovered.")
    if "kali_agent_scan" in assessment.get("runs", {}) or any(
        name.startswith("kali_url_scan") for name in assessment.get("runs", {})
    ):
        lines.extend(_kali_scope_lines(assessment))

    lines.extend(
        [
            "",
            "## Methodology",
            "",
            "- Static payload scans for prompt disclosure, system prompt disclosure, prompt injection, tool abuse, and secret extraction.",
            "- Active local service reconnaissance through compatible `/health`, `/metadata`, `/targets`, and `/invoke` endpoints when discovered.",
            "- Reconnaissance-driven dynamic prompt generation based on each agent's role, tools, boundaries, and configured secret names.",
            "- Optional local-model adaptive red-team planning when requested.",
            "- Optional Kali-backed recon and prompt probes when requested.",
            "- Rule-based detector evaluation with evidence capture and severity assignment.",
            "",
        ]
    )
    lines.extend(_observability_lines(assessment))
    lines.extend(_dynamic_generation_lines(assessment))
    lines.extend(_tool_execution_trace_lines(assessment))
    lines.extend(["## Risk Register", ""])

    if findings:
        lines.extend(
            [
                "| ID | Severity | Target | Attack | Status | Finding |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for finding in findings:
            reason = _escape_table(_safe_excerpt(finding["reason"], limit=220))
            lines.append(
                f"| {finding['id']} | {finding['severity']} | {finding['target']} | "
                f"{finding['attack']} | {finding['status']} | {reason} |"
            )
    else:
        lines.append("No confirmed failures or execution errors were recorded.")

    lines.extend(["", "## Findings Detail", ""])
    if findings:
        for finding in findings:
            lines.extend(
                [
                    f"### {finding['id']} - {finding['severity']} - {finding['target']}",
                    "",
                    f"- Run: `{finding['run']}`",
                    f"- Attack: `{finding['attack']}`",
                    f"- Status: `{finding['status']}`",
                    f"- Finding: {_safe_excerpt(finding['reason'], limit=600)}",
                    f"- Recommended remediation: {_remediation_for(finding)}",
                    "",
                    "Prompt:",
                    "",
                    "```text",
                    fenced_text(_safe_excerpt(finding["prompt"], limit=1200)),
                    "```",
                    "",
                    "Response excerpt:",
                    "",
                    "```text",
                    fenced_text(_safe_excerpt(finding["response"], limit=500)),
                    "```",
                    "",
                ]
            )
    else:
        lines.append("No finding details to report.")

    lines.extend([""])
    lines.extend(_reliability_lines(results))

    lines.extend(
        [
            "",
            "## Recommended Next Steps",
            "",
            "1. Rerun this assessment after any guardrail or tool-permission change.",
            "2. Keep fake lab secrets in tests and never commit real credentials.",
            "3. Add regression payloads for every confirmed failure.",
            "4. Review any ERROR or UNPARSED result as a possible blind spot.",
            "",
            "## Artifacts",
            "",
        ]
    )
    monitoring = assessment.get("monitoring") or {}
    for key in ("timeline_markdown", "events_jsonl"):
        if monitoring.get(key):
            lines.append(f"- `monitoring` {key}: `{monitoring[key]}`")
    for run_name, run in assessment.get("runs", {}).items():
        for key in ("report_path", "combined_report"):
            if run.get(key):
                lines.append(f"- `{run_name}` {key}: `{run[key]}`")

    return "\n".join(lines), {"generated_at": generated_at, "summary": summary, "findings": findings}


def write_enterprise_report(
    assessment,
    report_path=DEFAULT_REPORT_PATH,
    json_path=DEFAULT_JSON_PATH,
):
    markdown, report_data = build_enterprise_report(assessment)
    markdown_path = Path(report_path)
    json_report_path = Path(json_path)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_report_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.write_text(markdown, encoding="utf-8")
    json_report_path.write_text(
        json.dumps({"assessment": assessment, "report": report_data}, indent=2, default=str),
        encoding="utf-8",
    )
    return {"markdown_report": str(markdown_path), "json_report": str(json_report_path), **report_data}
