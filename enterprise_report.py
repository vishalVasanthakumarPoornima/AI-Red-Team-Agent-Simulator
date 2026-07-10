"""Enterprise-style reporting for natural-language red-team assessments."""

from datetime import datetime, timezone
from pathlib import Path
import json

from scanner.attack_runner import REPORTS_DIR, fenced_text, status_counts, truncate_text


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
                "target": result.get("target", "unknown"),
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


def _remediation_for(finding):
    attack = str(finding.get("attack", "")).lower()
    if "secret" in attack:
        return "Move secrets out of prompts and tools, enforce secret redaction, and add output filtering tests."
    if "prompt" in attack:
        return "Strengthen prompt isolation, refuse hidden-instruction disclosure, and regression-test known bypass prompts."
    if "tool" in attack:
        return "Add tool authorization checks, dry-run guards, scoped permissions, and audit logs before tool execution."
    if finding.get("status") == "ERROR":
        return "Fix service reliability or parser compatibility so failures cannot hide security findings."
    return "Review the affected agent policy, add a targeted guardrail, and rerun the red-team suite."


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
        f"- Confirmed failures: {summary['fail']}",
        f"- Execution or parser errors: {summary['error']}",
        f"- Active local services discovered: {len(active_agents)}",
        f"- Repository targets in scope: {len(targets)}",
        f"- Assessment runs executed: {', '.join(run_names) if run_names else 'none'}",
        f"- Reconnaissance probes completed: {dynamic_summary['reconnaissance']}",
        f"- Dynamic probes generated: {dynamic_summary['generated_payloads']}",
        "",
    ]

    if findings:
        highest = findings[0]["severity"]
        lines.append(
            f"Overall result: findings require remediation. Highest observed severity: {highest}."
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
            "## Risk Register",
            "",
        ]
    )

    if findings:
        lines.extend(
            [
                "| ID | Severity | Target | Attack | Status | Finding |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for finding in findings:
            reason = str(finding["reason"]).replace("|", "\\|")
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
                    f"- Finding: {finding['reason']}",
                    f"- Recommended remediation: {_remediation_for(finding)}",
                    "",
                    "Prompt:",
                    "",
                    "```text",
                    fenced_text(finding["prompt"]),
                    "```",
                    "",
                    "Response excerpt:",
                    "",
                    "```text",
                    fenced_text(truncate_text(finding["response"])),
                    "```",
                    "",
                ]
            )
    else:
        lines.append("No finding details to report.")

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
