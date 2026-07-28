#!/usr/bin/env python3
"""Build a sanitized, presentation-focused demo package from copied run artifacts."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from build_attack_walkthrough import kali_activity

SECRET_PATTERNS = [
    (re.compile(r"(?i)Bearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer <REDACTED>"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"), "<REDACTED_API_KEY>"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "<REDACTED_PRIVATE_KEY>"),
    (re.compile(r"(?i)(api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)(\s*[=:]\s*)[^\s,;\"']+"), r"\1\2<REDACTED>"),
    (re.compile(r"(?i)(authorization|cookie|set-cookie)(\s*[:=]\s*)[^\r\n]+"), r"\1\2<REDACTED>"),
    (re.compile(r"/Users/[^/\s\"']+"), "/Users/<USER>"),
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "<REDACTED_EMAIL>"),
    (re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?!\d)"), "<REDACTED_PHONE>"),
    (re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"), "<PRIVATE_IP>"),
    (re.compile(r"(?i)([?&](?:token|key|secret|password|signature)=)[^&#\s]+"), r"\1<REDACTED>"),
]


def redact_text(value: str) -> str:
    result = value
    for pattern, replacement in SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def sanitize(value: Any, key: str = "") -> Any:
    sensitive_key = re.search(r"(?i)(password|secret|token|api.?key|authorization|cookie|private.?key)", key)
    if sensitive_key and value not in (None, "", [], {}):
        return "<REDACTED>"
    if isinstance(value, dict):
        return {str(k): sanitize(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(item, key) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def find_first(data: Any, keys: tuple[str, ...], default: Any = None) -> Any:
    if isinstance(data, dict):
        for key in keys:
            if key in data and data[key] not in (None, ""):
                return data[key]
        for value in data.values():
            found = find_first(value, keys, None)
            if found not in (None, ""):
                return found
    elif isinstance(data, list):
        for value in data:
            found = find_first(value, keys, None)
            if found not in (None, ""):
                return found
    return default


def as_number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def finding_rows(run_dir: Path, report: dict[str, Any]) -> list[dict[str, Any]]:
    raw = load_json(run_dir / "findings.json", [])
    if isinstance(raw, dict):
        raw = raw.get("findings", [])
    if not raw:
        raw = report.get("findings", [])
        if isinstance(raw, dict):
            raw = raw.get("items", raw.get("findings", []))
    rows: list[dict[str, Any]] = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "id": item.get("finding_id") or item.get("id") or "—",
                "severity": str(item.get("severity") or "informational").title(),
                "status": str(item.get("status") or "unknown").replace("_", " ").title(),
                "category": str(item.get("category") or "uncategorized").replace("_", " "),
                "title": item.get("title") or item.get("name") or "Untitled finding",
                "description": item.get("description") or item.get("summary") or "",
                "remediation": item.get("remediation") or item.get("recommendation") or "",
            }
        )
    return sanitize(rows)


def baseline_summary(run_dir: Path | None) -> dict[str, Any]:
    if run_dir is None:
        return {"available": False}
    report = load_json(run_dir / "report.json", {})
    coverage = load_json(run_dir / "coverage.json", {})
    summary = load_json(run_dir / "dexter_summary.json", {})
    if not summary:
        summary = load_json(run_dir / "summary.json", {})
    probes = load_json(run_dir / "probe_results.json", [])
    findings = finding_rows(run_dir, report)
    severity_counts = Counter(item["severity"].lower() for item in findings)

    kali_summary = kali_activity(run_dir)
    kali_completed = int(kali_summary.get("completed_count", 0))

    overall_coverage = find_first(coverage, ("overall_percentage", "coverage_percentage", "percentage"), None)
    if overall_coverage is None:
        overall_coverage = find_first(report, ("coverage_percentage", "overall_percentage"), 0)

    status = find_first(summary, ("status",), None) or find_first(report, ("status",), "unknown")
    run_id = find_first(summary, ("run_id",), None) or find_first(report, ("run_id",), run_dir.name)
    target_id = find_first(summary, ("target_id",), None) or find_first(report, ("target_id", "stable_id"), "Dexter")
    profile = find_first(summary, ("profile",), None) or find_first(report, ("profile",), "standard")
    duration = find_first(summary, ("duration_seconds", "duration"), None) or find_first(report, ("duration_seconds", "duration"), None)
    error_count = find_first(summary, ("error_count",), None)
    if error_count is None:
        errors = report.get("errors", []) if isinstance(report, dict) else []
        error_count = len(errors) if isinstance(errors, list) else 0
    timeout_count = find_first(summary, ("timeout_count",), 0)
    unavailable_steps = find_first(summary, ("unavailable_steps",), None)
    if unavailable_steps is None:
        unavailable_steps = find_first(coverage, ("unavailable_steps",), 0)

    probe_list = probes if isinstance(probes, list) else probes.get("results", []) if isinstance(probes, dict) else []
    completed_probes = sum(1 for p in probe_list if isinstance(p, dict) and str(p.get("status", "")).lower() in {"complete", "completed", "success", "passed", "finding", "failed"})

    return sanitize(
        {
            "available": True,
            "run_id": run_id,
            "target_id": target_id,
            "profile": profile,
            "status": status,
            "duration_seconds": duration,
            "coverage_percentage": round(as_number(overall_coverage), 2),
            "completed_probes": completed_probes or len(probe_list),
            "finding_count": len(findings),
            "severity_counts": dict(severity_counts),
            "findings": findings,
            "kali_checks_completed": kali_completed,
            "kali_evidence_present": bool(kali_summary.get("evidence_present")),
            "kali_tools": kali_summary.get("tools", []),
            "kali_tunnel_observed": bool(kali_summary.get("tunnel_observed")),
            "error_count": int(as_number(error_count)),
            "timeout_count": int(as_number(timeout_count)),
            "unavailable_steps": int(as_number(unavailable_steps)),
            "report_files": [name for name in ("report.md", "report.json", "manifest.json") if (run_dir / name).exists()],
            "enterprise_files_present": sorted(path.name for path in run_dir.glob("report_v7.*")),
        }
    )


def adaptive_summary(run_dir: Path | None) -> dict[str, Any]:
    if run_dir is None:
        return {"available": False}
    data = load_json(run_dir / "adaptive_summary.json", {})
    if not isinstance(data, dict) or not data:
        return {"available": False, "run_id": run_dir.name}
    result = {
        "available": True,
        "run_id": data.get("run_id", run_dir.name),
        "mode": data.get("mode", "guided"),
        "status": data.get("status", "unknown"),
        "rounds": data.get("rounds", 0),
        "probes": data.get("probes", 0),
        "model_calls": data.get("model_calls", 0),
        "accepted_proposals": data.get("accepted_proposals", 0),
        "rejected_proposals": data.get("rejected_proposals", 0),
        "novel_proposals": data.get("novel_proposals", 0),
        "duplicate_rate": data.get("duplicate_rate", 0),
        "categories_covered": data.get("categories_covered", []),
        "stop_reason": data.get("stop_reason", "unknown"),
        "limitations": data.get("limitations", []),
    }
    return sanitize(result)


def safe_copy_reports(run_dir: Path | None, presentation: Path, prefix: str) -> None:
    if run_dir is None:
        return
    for source_name in ("report.md", "report.json", "findings.json", "coverage.json", "adaptive_summary.json", "adaptive_rounds.json", "proposal_rejections.json", "novelty.json", "stop_decision.json", "adaptive_configuration.json", "model_roles.json"):
        source = run_dir / source_name
        if not source.exists():
            continue
        safe_names = {
            "report.md": f"{prefix}_report_safe.md",
            "report.json": f"{prefix}_report_safe.json",
            "findings.json": f"{prefix}_findings_safe.json",
            "coverage.json": f"{prefix}_coverage_safe.json",
            "adaptive_summary.json": f"{prefix}_summary_safe.json",
            "adaptive_rounds.json": f"{prefix}_rounds_safe.json",
            "proposal_rejections.json": f"{prefix}_rejections_safe.json",
            "novelty.json": f"{prefix}_novelty_safe.json",
            "stop_decision.json": f"{prefix}_stop_decision_safe.json",
            "adaptive_configuration.json": f"{prefix}_configuration_safe.json",
            "model_roles.json": f"{prefix}_model_roles_safe.json",
        }
        destination = presentation / safe_names[source_name]
        if source.suffix == ".json":
            data = sanitize(load_json(source, {}))
            destination.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        else:
            destination.write_text(redact_text(source.read_text(encoding="utf-8", errors="replace")), encoding="utf-8")


def format_value(value: Any, suffix: str = "") -> str:
    if value in (None, ""):
        return "—"
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return f"{value}{suffix}"


def markdown(summary: dict[str, Any]) -> str:
    baseline = summary["baseline"]
    adaptive = summary["adaptive"]
    findings = baseline.get("findings", [])
    lines = [
        "# AI Agent Red Team Simulator — Demo Summary",
        "",
        f"**Demo mode:** {summary['demo_mode'].title()}",
        f"**Generated:** {summary['generated_at']}",
        f"**Platform version:** {summary['platform_version']}",
        f"**Source commit:** `{summary['source_commit']}`",
        f"**Phase 7 reporting state:** {summary['phase7_status']}",
        "",
        "> This summary is sanitized for presentation. Raw copied evidence is under `../evidence/` and should not be shown publicly without review.",
        "",
        "## What was demonstrated",
        "",
        "The platform assessed an authorized, loopback-only Dexter AI deployment. It validated scope and readiness, ran deterministic API and AI-security probes, used Kali through a bounded SSH tunnel when available, generated findings and coverage, and stored reproducible artifacts.",
        "",
        "## Baseline Dexter + Kali result",
        "",
    ]
    if baseline.get("available"):
        lines.extend(
            [
                f"- Run ID: `{baseline.get('run_id')}`",
                f"- Status: **{baseline.get('status')}**",
                f"- Profile: `{baseline.get('profile')}`",
                f"- Coverage: **{format_value(baseline.get('coverage_percentage'), '%')}**",
                f"- Completed probes recorded: **{baseline.get('completed_probes', 0)}**",
                f"- Findings: **{baseline.get('finding_count', 0)}**",
                f"- Kali checks completed: **{baseline.get('kali_checks_completed', 0)}**",
                f"- Errors / timeouts: **{baseline.get('error_count', 0)} / {baseline.get('timeout_count', 0)}**",
                f"- Unavailable steps: **{baseline.get('unavailable_steps', 0)}**",
                "",
            ]
        )
    else:
        lines.extend(["No baseline run was available.", ""])

    lines.extend(["## Findings", ""])
    if findings:
        for finding in findings:
            lines.extend(
                [
                    f"### {finding['severity']} — {finding['title']}",
                    "",
                    f"- Status: {finding['status']}",
                    f"- Category: {finding['category']}",
                ]
            )
            if finding.get("description"):
                lines.extend(["", finding["description"]])
            if finding.get("remediation"):
                lines.extend(["", f"**Recommended action:** {finding['remediation']}"])
            lines.append("")
    else:
        lines.extend(["No findings were available in the selected run.", ""])

    adaptive_heading = "Model-proposed adaptive follow-up" if str(adaptive.get("mode", "")).lower() == "adaptive" else "Guided adaptive follow-up"
    lines.extend([f"## {adaptive_heading}", ""])
    if adaptive.get("available"):
        lines.extend(
            [
                f"- Run ID: `{adaptive.get('run_id')}`",
                f"- Mode: `{adaptive.get('mode')}`",
                f"- Status: **{adaptive.get('status')}**",
                f"- Rounds: **{adaptive.get('rounds')}**",
                f"- Additional probes: **{adaptive.get('probes')}**",
                f"- Accepted / rejected proposals: **{adaptive.get('accepted_proposals')} / {adaptive.get('rejected_proposals')}**",
                f"- Model calls: **{adaptive.get('model_calls')}**",
                f"- Stop reason: **{str(adaptive.get('stop_reason')).replace('_', ' ')}**",
                "",
                (
                    "`model_calls: 0` is expected in guided mode: registered follow-up probes are selected deterministically."
                    if str(adaptive.get("mode", "")).lower() == "guided"
                    else "In model-proposed mode, model output is treated only as an untrusted typed proposal. Deterministic policy decides whether a registered probe may execute."
                ),
                "",
            ]
        )
    else:
        lines.extend(["No adaptive follow-up artifact was available.", ""])

    lines.extend(
        [
            "## How to interpret coverage",
            "",
            "Coverage is the fraction of the planned assessment surface that was exercised. It is **not** a percentage of how secure Dexter is. An unavailable capability remains unavailable; it is not converted into a pass.",
            "",
            "## Attack walkthrough",
            "",
            "Open `ATTACK_WALKTHROUGH.html` for a step-by-step explanation of the baseline probes, Kali evidence, and adaptive categories.",
            "",
            "## Evidence and integrity",
            "",
            "- Sanitized presentation files are in this folder.",
            "- Raw copied artifacts are under `../evidence/`.",
            "- `../INTEGRITY.sha256` records SHA-256 hashes for every packaged file except the hash file itself.",
            "- Run `VERIFY_LATEST.command` from the demo folder to verify the package.",
            "",
            "## Important limitations",
            "",
            "- Findings are security evidence requiring engineering review, not compliance certification.",
            "- Retrieval/vector coverage is unavailable when Dexter does not configure those services.",
            "- Baseline and adaptive phases may remain separate runs in the verified Phase 6 workflow.",
            "- Experimental or uncommitted Phase 7 code is not automatically invoked by this demo.",
            "- Raw health/settings evidence may contain operational metadata and should not be displayed publicly.",
            "",
            "## Strong closing statement",
            "",
            "> This is a reproducible, authorized assessment showing exactly what was tested, what failed, what was unavailable, and what evidence supports each conclusion. It does not claim that the target is completely secure or insecure.",
            "",
        ]
    )
    return "\n".join(lines)


def html_page(summary: dict[str, Any]) -> str:
    baseline = summary["baseline"]
    adaptive = summary["adaptive"]
    dynamic_result = summary.get("dynamic_result", {})
    findings = baseline.get("findings", [])
    counts = baseline.get("severity_counts", {})
    cards = [
        ("Coverage", format_value(baseline.get("coverage_percentage"), "%")),
        ("Findings", str(baseline.get("finding_count", 0))),
        ("Kali checks", str(baseline.get("kali_checks_completed", 0))),
        ("Adaptive probes", str(adaptive.get("probes", 0) if adaptive.get("available") else 0)),
        ("Errors", str(baseline.get("error_count", 0))),
        ("Stop reason", str(adaptive.get("stop_reason", "baseline complete")).replace("_", " ")),
    ]
    if dynamic_result.get("proper_result") is not None:
        cards.append(("Terminal result", "validated" if dynamic_result.get("proper_result") else "incomplete"))
    card_html = "".join(f'<div class="card"><span>{html.escape(label)}</span><strong>{html.escape(value)}</strong></div>' for label, value in cards)
    finding_html = ""
    for finding in findings:
        sev = finding["severity"].lower()
        finding_html += (
            f'<article class="finding {html.escape(sev)}">'
            f'<div class="finding-head"><span class="badge">{html.escape(finding["severity"])}</span>'
            f'<h3>{html.escape(str(finding["title"]))}</h3></div>'
            f'<p><b>Status:</b> {html.escape(str(finding["status"]))} &nbsp; '
            f'<b>Category:</b> {html.escape(str(finding["category"]))}</p>'
            f'<p>{html.escape(str(finding.get("description", "")))}</p>'
            f'{f"<p><b>Recommended action:</b> {html.escape(str(finding.get("remediation")))}</p>" if finding.get("remediation") else ""}'
            f'</article>'
        )
    if not finding_html:
        finding_html = "<p>No findings were available in the selected run.</p>"

    phase7_note = html.escape(str(summary["phase7_status"]))
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Red Team Demo Summary</title>
<style>
:root{{--bg:#0b1020;--panel:#131a2d;--text:#edf2ff;--muted:#aab5d1;--accent:#73a7ff;--line:#28324d;--high:#ff6b6b;--low:#f0c36a;}}
*{{box-sizing:border-box}} body{{margin:0;background:linear-gradient(145deg,#080d19,#101831);color:var(--text);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
main{{max-width:1100px;margin:auto;padding:42px 24px 72px}} h1{{font-size:42px;line-height:1.1;margin:0 0 12px}} h2{{margin-top:42px;border-bottom:1px solid var(--line);padding-bottom:10px}} h3{{margin:0}} .eyebrow{{color:var(--accent);font-weight:700;letter-spacing:.08em;text-transform:uppercase}} .subtitle,.muted{{color:var(--muted)}} .banner{{background:#17213a;border:1px solid #365286;border-radius:12px;padding:16px 18px;margin:24px 0}} .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px}} .card{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;min-height:105px}} .card span{{display:block;color:var(--muted);font-size:14px}} .card strong{{display:block;font-size:25px;margin-top:8px;word-break:break-word}} .finding{{background:var(--panel);border:1px solid var(--line);border-left:5px solid var(--accent);border-radius:12px;padding:18px;margin:14px 0}} .finding.high{{border-left-color:var(--high)}} .finding.low{{border-left-color:var(--low)}} .finding-head{{display:flex;gap:12px;align-items:center}} .badge{{font-size:12px;font-weight:800;letter-spacing:.05em;background:#2b3654;border-radius:999px;padding:5px 9px}} code{{background:#11182a;padding:2px 6px;border-radius:6px}} a{{color:#9fc1ff}} table{{width:100%;border-collapse:collapse}} td{{border-bottom:1px solid var(--line);padding:10px 4px}} td:first-child{{color:var(--muted)}} .footer{{margin-top:50px;color:var(--muted);font-size:14px}} @media print{{body{{background:white;color:black}} .card,.finding,.banner{{background:white;border-color:#bbb}} .muted,.subtitle,.card span,.footer{{color:#444}}}}
</style>
</head>
<body><main>
<div class="eyebrow">Authorized local AI security assessment</div>
<h1>AI Agent Red Team Simulator</h1>
<p class="subtitle">Sanitized presentation summary generated from copied run artifacts.</p>
<div class="banner"><b>Demo mode:</b> {html.escape(str(summary['demo_mode']).title())} &nbsp; <b>Platform:</b> {html.escape(str(summary['platform_version']))}<br><b>Phase 7 state:</b> {phase7_note}<br><span class="muted">Raw evidence is stored separately and is not opened automatically.</span></div>
<div class="grid">{card_html}</div>
<h2>Assessment identity</h2>
<table>
<tr><td>Baseline run</td><td><code>{html.escape(str(baseline.get('run_id','unavailable')))}</code></td></tr>
<tr><td>Target</td><td>{html.escape(str(baseline.get('target_id','Dexter')))}</td></tr>
<tr><td>Profile</td><td>{html.escape(str(baseline.get('profile','standard')))}</td></tr>
<tr><td>Status</td><td>{html.escape(str(baseline.get('status','unknown')))}</td></tr>
<tr><td>Unavailable steps</td><td>{html.escape(str(baseline.get('unavailable_steps',0)))}</td></tr>
<tr><td>Adaptive run</td><td><code>{html.escape(str(adaptive.get('run_id','unavailable')))}</code></td></tr>
<tr><td>Adaptive model calls</td><td>{html.escape(str(adaptive.get('model_calls',0) if adaptive.get('available') else '—'))}</td></tr>
<tr><td>Adaptive terminal result</td><td>{html.escape('validated' if dynamic_result.get('proper_result') else ('incomplete' if dynamic_result else 'not evaluated'))}</td></tr>
</table>
<h2>Findings</h2>{finding_html}
<h2>What this proves</h2>
<p>The platform executed a bounded assessment against an explicitly authorized local target, preserved structured results, and produced evidence that can be independently reviewed. The result records findings, coverage, unavailable capabilities, errors, and stop conditions rather than converting missing tests into passes.</p>
<h2>What this does not prove</h2>
<p>Coverage is not a security percentage. A finding does not automatically prove broad exploitability, and this report is not a compliance certification. Root-cause analysis and remediation verification remain engineering tasks.</p>
<h2>Files to show next</h2>
<ul><li><a href="ATTACK_WALKTHROUGH.html">Attack walkthrough</a></li><li><a href="DEMO_SUMMARY.md">DEMO_SUMMARY.md</a></li><li><a href="DYNAMIC_RESULT.md">Dynamic terminal-result validation</a></li><li><a href="baseline_report_safe.md">Sanitized baseline report</a></li><li><a href="baseline_report_safe.json">Sanitized baseline JSON</a></li><li><a href="adaptive_summary_safe.json">Sanitized adaptive summary</a></li></ul>
<p class="footer">Generated {html.escape(str(summary['generated_at']))}. Package hashes are recorded in ../INTEGRITY.sha256.</p>
</main></body></html>"""


def write_integrity(output: Path) -> None:
    rows: list[str] = []
    for path in sorted(output.rglob("*")):
        if not path.is_file() or path.name == "INTEGRITY.sha256":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(f"{digest}  {path.relative_to(output).as_posix()}")
    (output / "INTEGRITY.sha256").write_text("\n".join(rows) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--adaptive", type=Path)
    parser.add_argument("--phase7-status", default="unavailable")
    parser.add_argument("--platform-version", default="unknown")
    parser.add_argument("--source-commit", default="unknown")
    args = parser.parse_args()

    presentation = args.output / "presentation"
    presentation.mkdir(parents=True, exist_ok=True)

    baseline = baseline_summary(args.baseline)
    adaptive = adaptive_summary(args.adaptive)
    dynamic_result_path = presentation / "DYNAMIC_RESULT.json"
    dynamic_result = load_json(dynamic_result_path, {})
    dynamic_md = presentation / "DYNAMIC_RESULT.md"
    if not dynamic_md.exists():
        dynamic_md.write_text(
            "# Dynamic Adaptive Result\n\nThis package did not run the model-proposed dynamic mode, so no dynamic terminal-result validation was performed.\n",
            encoding="utf-8",
        )
    summary = sanitize(
        {
            "schema_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "demo_mode": args.mode,
            "platform_version": args.platform_version,
            "source_commit": args.source_commit,
            "phase7_status": args.phase7_status,
            "baseline": baseline,
            "adaptive": adaptive,
            "dynamic_result": dynamic_result,
        }
    )

    (presentation / "DEMO_SUMMARY.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (presentation / "DEMO_SUMMARY.md").write_text(markdown(summary), encoding="utf-8")
    (presentation / "OPEN_ME_FIRST.html").write_text(html_page(summary), encoding="utf-8")

    safe_copy_reports(args.baseline, presentation, "baseline")
    safe_copy_reports(args.adaptive, presentation, "adaptive")

    (args.output / "README.txt").write_text(
        "Open presentation/OPEN_ME_FIRST.html first.\n"
        "The presentation folder is sanitized.\n"
        "The evidence folder contains copied raw artifacts and should be treated as private.\n"
        "Run the demo folder's VERIFY_LATEST.command to verify INTEGRITY.sha256.\n",
        encoding="utf-8",
    )
    write_integrity(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
