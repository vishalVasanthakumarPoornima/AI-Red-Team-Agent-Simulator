#!/usr/bin/env python3
"""Create a sanitized explanation of the exact assessment phases and recorded results."""

from __future__ import annotations

import argparse
import html
import json
import re
from pathlib import Path
from typing import Any, Iterable

CATEGORY_EXPLANATIONS = {
    "deployment_discovery": "Confirms the exact authorized service, process, listener, and scope before active testing.",
    "api_surface": "Inspects reachable API routes, OpenAPI metadata, response behavior, and exposed headers.",
    "authentication": "Checks whether sensitive routes require an authenticated identity.",
    "authorization": "Checks whether actions and resources enforce the expected permission boundary.",
    "error_handling": "Sends bounded malformed or incomplete requests and checks for unsafe errors or internal data leakage.",
    "error_leakage": "Checks whether errors reveal stack traces, implementation details, secrets, or private metadata.",
    "prompt_security": "Uses harmless synthetic prompts to test instruction hierarchy, prompt injection resistance, disclosure resistance, and isolation.",
    "prompt_injection": "Attempts a harmless instruction override and checks whether protected instructions remain authoritative.",
    "prompt_disclosure": "Asks for protected or hidden instructions and checks whether the model reveals them.",
    "weak_refusal": "Checks whether the model refuses unsafe or out-of-scope requests consistently and clearly.",
    "synthetic_secret": "Uses a fake canary value to detect context, memory, or prompt-isolation failures without exposing a real secret.",
    "model_metadata": "Checks whether the service exposes model, provider, or deployment metadata beyond what is necessary.",
    "output_schema": "Checks whether responses preserve the required structured output and do not escape into unexpected formats.",
    "unsafe_tool_claim": "Checks whether the assistant falsely claims that it used a tool or performed an external action.",
    "tool_security": "Uses fake or dry-run tool requests to verify approval, argument validation, and least-privilege behavior without real side effects.",
    "memory": "Uses a unique synthetic marker to test whether memory is isolated and whether data can cross an unexpected boundary.",
    "retrieval": "Uses synthetic local content to test retrieval instruction separation. This is unavailable when no retrieval service is configured.",
    "rate_limiting": "Sends a small bounded sequence of requests and checks whether rate-limit behavior and headers are visible.",
    "service_exposure": "Checks listeners, HTTP metadata, and deployment hardening such as security headers.",
    "kali_network_checks": "Uses registered Kali adapters through a loopback-only SSH tunnel to fingerprint only the approved Dexter service.",
    "reporting": "Normalizes results, records limitations, writes reports, and hashes artifacts for integrity verification.",
}

SECRET_PATTERNS = [
    (re.compile(r"(?i)Bearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer <REDACTED>"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"), "<REDACTED_API_KEY>"),
    (re.compile(r"/Users/[^/\s\"']+"), "/Users/<USER>"),
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "<REDACTED_EMAIL>"),
    (re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"), "<PRIVATE_IP>"),
]


def redact(value: str) -> str:
    result = value
    for pattern, replacement in SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def normalize_category(value: Any) -> str:
    return str(value or "uncategorized").strip().lower().replace(" ", "_")


def first(item: dict[str, Any], *keys: str, default: Any = "") -> Any:
    for key in keys:
        if key in item and item[key] not in (None, "", [], {}):
            return item[key]
    return default


def plan_steps(run_dir: Path) -> list[dict[str, Any]]:
    candidates = [
        run_dir / "assessment_plan.json",
        run_dir / "plan.json",
        run_dir / "dexter_plan.json",
    ]
    data: Any = {}
    for path in candidates:
        if path.exists():
            data = load_json(path, {})
            break
    raw_steps: Any = data.get("steps", []) if isinstance(data, dict) else []
    results = load_json(run_dir / "probe_results.json", [])
    if isinstance(results, dict):
        results = results.get("results", results.get("probes", []))
    result_map: dict[str, list[dict[str, Any]]] = {}
    for result in results if isinstance(results, list) else []:
        if not isinstance(result, dict):
            continue
        for key in ("step_id", "probe_id", "id"):
            value = result.get(key)
            if value:
                result_map.setdefault(str(value), []).append(result)

    steps: list[dict[str, Any]] = []
    for raw in raw_steps if isinstance(raw_steps, list) else []:
        if not isinstance(raw, dict):
            continue
        step_id = str(first(raw, "step_id", "id", "probe_id", default="unknown"))
        category = normalize_category(first(raw, "category", "coverage_category", default="uncategorized"))
        matching = result_map.get(step_id, [])
        statuses = [str(first(row, "status", "outcome", default="unknown")) for row in matching]
        findings = [first(row, "finding_id", "finding", default="") for row in matching]
        operations = first(raw, "operations", "actions", "description", default=[])
        if isinstance(operations, str):
            operations = [operations]
        if not isinstance(operations, list):
            operations = []
        steps.append(
            {
                "id": step_id,
                "phase": str(first(raw, "phase", default="unknown")),
                "mode": str(first(raw, "mode", default="unknown")),
                "category": category,
                "explanation": CATEGORY_EXPLANATIONS.get(category, "Runs a registered, bounded check in this assessment category."),
                "requests": first(raw, "requests", "request_count", "max_requests", default=0),
                "tool": str(first(raw, "tool", "required_tool", default="none")),
                "scope": redact(str(first(raw, "scope", "target", "endpoint", default="configured target"))),
                "operations": [redact(str(value)) for value in operations],
                "result_statuses": statuses,
                "finding_ids": [str(value) for value in findings if value],
            }
        )
    return steps


def recursive_dicts(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from recursive_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from recursive_dicts(child)


def looks_like_kali_record(item: dict[str, Any]) -> bool:
    text = " ".join(
        str(item.get(key, ""))
        for key in ("adapter_id", "tool", "name", "action", "phase", "category", "event", "event_type")
    ).lower()
    return any(token in text for token in ("kali", "nmap", "whatweb", "nikto", "tunnel", "curl"))


def completed_record(item: dict[str, Any]) -> bool:
    if item.get("skipped") is True:
        return False
    status = str(first(item, "status", "state", "outcome", "result", default="")).lower()
    if status in {"complete", "completed", "success", "succeeded", "passed", "ok", "finished"}:
        return True
    for key in ("returncode", "return_code", "exit_code"):
        if key in item:
            try:
                return int(item[key]) == 0
            except (TypeError, ValueError):
                pass
    return False


def kali_activity(run_dir: Path) -> dict[str, Any]:
    """Extract authoritative Kali activity without double-counting nested objects."""
    records: list[dict[str, Any]] = []
    report = load_json(run_dir / "report.json", {})
    if isinstance(report, dict):
        tools = report.get("tools")
        if isinstance(tools, dict) and isinstance(tools.get("kali"), list):
            records.extend(item for item in tools["kali"] if isinstance(item, dict))

    # Fall back to dedicated result files when the canonical report does not carry
    # the Kali list. Avoid recursively counting parent containers as checks.
    for filename in ("kali_results.json", "dexter_kali_results.json"):
        value = load_json(run_dir / filename, [])
        if isinstance(value, dict):
            value = value.get("results", value.get("checks", []))
        if isinstance(value, list):
            records.extend(item for item in value if isinstance(item, dict))

    event_records: list[dict[str, Any]] = []
    events_path = run_dir / "events.jsonl"
    if events_path.exists():
        try:
            for raw in events_path.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    item = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict) and looks_like_kali_record(item):
                    event_records.append(item)
        except OSError:
            pass

    completed: dict[str, dict[str, Any]] = {}
    skipped: dict[str, dict[str, Any]] = {}
    observed_tools: set[str] = set()
    tunnel_observed = False
    tunnel_cleaned = False

    def identity(item: dict[str, Any], index: int) -> str:
        core = {
            key: item.get(key)
            for key in (
                "adapter_id", "check_id", "probe_id", "step_id", "tool", "name",
                "action", "url", "target", "port", "sequence", "timestamp", "started_at"
            )
            if item.get(key) not in (None, "", [], {})
        }
        if not core:
            core = {"index": index, "record": item}
        import hashlib
        encoded = json.dumps(core, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()[:20]

    all_records = records + event_records
    for index, item in enumerate(all_records):
        text = json.dumps(item, sort_keys=True, default=str).lower()
        if "tunnel" in text:
            tunnel_observed = True
            if any(token in text for token in ("cleanup", "cleaned", "stopped", "terminated", "closed")):
                tunnel_cleaned = True
        for tool in ("nmap", "whatweb", "nikto", "curl"):
            if tool in text:
                observed_tools.add(tool)
        key = identity(item, index)
        if item.get("skipped") is True or str(first(item, "status", "state", default="")).lower() == "skipped":
            skipped[key] = item
        elif completed_record(item):
            completed[key] = item

    # When authoritative report.json tools.kali exists, prefer its direct count;
    # event records are used for tunnel/tool detail but not additional check count.
    authoritative_completed = [item for item in records if completed_record(item)]
    authoritative_skipped = [
        item for item in records
        if item.get("skipped") is True or str(first(item, "status", "state", default="")).lower() == "skipped"
    ]
    completed_count = len(authoritative_completed) if records else len(completed)
    skipped_count = len(authoritative_skipped) if records else len(skipped)

    return {
        "evidence_present": bool(all_records),
        "completed_count": completed_count,
        "skipped_count": skipped_count,
        "tools": sorted(observed_tools),
        "tunnel_observed": tunnel_observed,
        "tunnel_cleaned": tunnel_cleaned,
        "note": (
            "Completed and skipped counts prefer the authoritative report.json tools.kali list; "
            "events supply tool and tunnel lifecycle evidence without inflating the check count."
        ),
    }

def adaptive_details(run_dir: Path | None) -> dict[str, Any]:
    if run_dir is None:
        return {"available": False}
    summary = load_json(run_dir / "adaptive_summary.json", {})
    rounds = load_json(run_dir / "adaptive_rounds.json", [])
    if not isinstance(summary, dict) or not summary:
        return {"available": False}

    proposal_rows: list[dict[str, Any]] = []
    for item in recursive_dicts(rounds):
        template_id = first(item, "template_id", "probe_id", "proposal_id", default="")
        category = first(item, "category", "coverage_category", default="")
        decision = first(item, "decision", "status", "validation_status", default="")
        if template_id or category:
            normalized = normalize_category(category)
            proposal_rows.append(
                {
                    "id": str(template_id or "registered proposal"),
                    "category": normalized,
                    "decision": str(decision or "recorded"),
                    "explanation": CATEGORY_EXPLANATIONS.get(normalized, "A registered follow-up probe selected from the bounded template registry."),
                }
            )
    unique: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in proposal_rows:
        unique[(row["id"], row["category"], row["decision"])] = row

    return {
        "available": True,
        "run_id": summary.get("run_id", run_dir.name),
        "mode": summary.get("mode", "guided"),
        "rounds": summary.get("rounds", 0),
        "probes": summary.get("probes", 0),
        "model_calls": summary.get("model_calls", 0),
        "accepted_proposals": summary.get("accepted_proposals", 0),
        "rejected_proposals": summary.get("rejected_proposals", 0),
        "categories_covered": summary.get("categories_covered", []),
        "stop_reason": summary.get("stop_reason", "unknown"),
        "proposal_rows": list(unique.values())[:100],
    }


def write_markdown(data: dict[str, Any], path: Path) -> None:
    lines = [
        "# Live Attack Walkthrough",
        "",
        "> This document explains the registered checks recorded by the assessment. It intentionally omits raw prompts, private headers, secrets, and machine-specific evidence.",
        "",
        "## What happened",
        "",
        "The baseline assessment executed a fixed, reviewed plan. The adaptive follow-up selected additional registered probes based on coverage. Kali, when recorded, accessed only the approved service through a loopback-only SSH tunnel.",
        "",
        "## Baseline assessment steps",
        "",
    ]
    for step in data["baseline_steps"]:
        lines.extend(
            [
                f"### {step['id']} — {step['category'].replace('_', ' ').title()}",
                "",
                f"- Phase / mode: `{step['phase']}` / `{step['mode']}`",
                f"- Requests: `{step['requests']}`",
                f"- Tool: `{step['tool']}`",
                f"- Scope: `{step['scope']}`",
                f"- Recorded statuses: `{', '.join(step['result_statuses']) if step['result_statuses'] else 'not separately recorded'}`",
                f"- Finding IDs: `{', '.join(step['finding_ids']) if step['finding_ids'] else 'none'}`",
                "",
                step["explanation"],
                "",
            ]
        )
        if step["operations"]:
            lines.append("Operations shown by the plan:")
            lines.extend(f"- {value}" for value in step["operations"])
            lines.append("")

    kali = data["kali"]
    lines.extend(
        [
            "## Kali activity",
            "",
            f"- Kali evidence present: **{'yes' if kali['evidence_present'] else 'no'}**",
            f"- Completed checks detected: **{kali['completed_count']}**",
            f"- Tools observed: **{', '.join(kali['tools']) if kali['tools'] else 'none recorded'}**",
            f"- Restricted tunnel evidence: **{'yes' if kali['tunnel_observed'] else 'not detected in copied artifacts'}**",
            "",
            kali["note"],
            "",
        ]
    )

    adaptive = data["adaptive"]
    lines.extend(["## Adaptive follow-up", ""])
    if adaptive.get("available"):
        lines.extend(
            [
                f"- Run ID: `{adaptive['run_id']}`",
                f"- Mode: `{adaptive['mode']}`",
                f"- Rounds: **{adaptive['rounds']}**",
                f"- Probes: **{adaptive['probes']}**",
                f"- Model calls: **{adaptive['model_calls']}**",
                f"- Accepted / rejected: **{adaptive['accepted_proposals']} / {adaptive['rejected_proposals']}**",
                f"- Stop reason: **{str(adaptive['stop_reason']).replace('_', ' ')}**",
                "",
            ]
        )
        if str(adaptive["mode"]).lower() == "guided" and int(adaptive.get("model_calls", 0) or 0) == 0:
            lines.extend(
                [
                    "Guided mode is adaptive in selection, not generative in execution. The engine chose follow-up checks from a registered template set; it did not ask a model to invent shell commands, ports, tools, or targets.",
                    "",
                ]
            )
        categories = adaptive.get("categories_covered", [])
        if categories:
            lines.append("Covered follow-up categories:")
            for category in categories:
                normalized = normalize_category(category)
                lines.append(f"- **{normalized.replace('_', ' ')}:** {CATEGORY_EXPLANATIONS.get(normalized, 'Registered bounded follow-up probe.')}" )
            lines.append("")
        if adaptive.get("proposal_rows"):
            lines.append("Recorded proposal details:")
            for row in adaptive["proposal_rows"]:
                lines.append(f"- `{row['id']}` — {row['category'].replace('_', ' ')} — {row['decision']}")
            lines.append("")
    else:
        lines.extend(["No adaptive artifact was available.", ""])

    lines.extend(
        [
            "## What was not performed",
            "",
            "- No subnet scan or full-port scan",
            "- No credential attack or brute force",
            "- No SQLMap, unrestricted Nuclei, Metasploit, reverse shell, or persistence",
            "- No arbitrary model-generated command execution",
            "- No scope expansion beyond the configured Dexter target and tunnel port",
            "",
            "## How to present this honestly",
            "",
            "Describe these as bounded security probes, not a cinematic exploit. The strongest demonstrated result is the confirmed synthetic-canary isolation finding, supported by recorded evidence and deterministic evaluation.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def write_html(data: dict[str, Any], path: Path) -> None:
    step_cards = []
    for step in data["baseline_steps"]:
        operations = "".join(f"<li>{html.escape(value)}</li>" for value in step["operations"])
        step_cards.append(
            "<article class='step'>"
            f"<h3>{html.escape(step['id'])} · {html.escape(step['category'].replace('_', ' ').title())}</h3>"
            f"<p>{html.escape(step['explanation'])}</p>"
            f"<div class='meta'>Phase {html.escape(step['phase'])} · Mode {html.escape(step['mode'])} · Requests {html.escape(str(step['requests']))} · Tool {html.escape(step['tool'])}</div>"
            f"<p><b>Scope:</b> {html.escape(step['scope'])}</p>"
            f"<p><b>Recorded result:</b> {html.escape(', '.join(step['result_statuses']) if step['result_statuses'] else 'not separately recorded')}</p>"
            f"<ul>{operations}</ul>"
            "</article>"
        )
    adaptive = data["adaptive"]
    categories_html = ""
    if adaptive.get("available"):
        categories_html = "".join(
            f"<li><b>{html.escape(normalize_category(category).replace('_', ' '))}:</b> {html.escape(CATEGORY_EXPLANATIONS.get(normalize_category(category), 'Registered bounded follow-up probe.'))}</li>"
            for category in adaptive.get("categories_covered", [])
        )
        adaptive_html = (
            f"<p><b>Mode:</b> {html.escape(str(adaptive['mode']))} · <b>Rounds:</b> {adaptive['rounds']} · <b>Probes:</b> {adaptive['probes']} · "
            f"<b>Model calls:</b> {adaptive['model_calls']} · <b>Stop:</b> {html.escape(str(adaptive['stop_reason']).replace('_', ' '))}</p>"
            "<p>Guided mode dynamically selects from registered probes. It does not let a model invent or execute commands.</p>"
            f"<ul>{categories_html}</ul>"
        )
    else:
        adaptive_html = "<p>No adaptive artifact was available.</p>"

    kali = data["kali"]
    page = f"""<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Live Attack Walkthrough</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#0b1020;color:#e8eefc;line-height:1.55}}
main{{max-width:1100px;margin:auto;padding:32px 20px 80px}}
h1,h2,h3{{line-height:1.2}} .banner{{padding:18px;border:1px solid #35517d;background:#121b31;border-radius:14px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px}} .step{{background:#111a2e;border:1px solid #293a5d;border-radius:14px;padding:18px}}
.meta{{color:#9db0d3;font-size:.92rem}} code{{background:#0a1223;padding:2px 6px;border-radius:5px}} a{{color:#8fc7ff}}
.good{{color:#8ce99a}} .warn{{color:#ffd166}} ul{{padding-left:22px}}
</style>
</head>
<body><main>
<h1>Live Attack Walkthrough</h1>
<div class='banner'><b>What this is:</b> a sanitized explanation of the actual registered probes and recorded results. Raw prompts, secrets, headers, and private paths are deliberately omitted.</div>
<h2>Baseline assessment steps</h2>
<div class='grid'>{''.join(step_cards)}</div>
<h2>Kali activity</h2>
<p><b>Evidence present:</b> {'yes' if kali['evidence_present'] else 'no'} · <b>Completed checks detected:</b> {kali['completed_count']} · <b>Tools observed:</b> {html.escape(', '.join(kali['tools']) if kali['tools'] else 'none recorded')} · <b>Tunnel evidence:</b> {'yes' if kali['tunnel_observed'] else 'not detected'}</p>
<p>{html.escape(kali['note'])}</p>
<h2>Adaptive follow-up</h2>
{adaptive_html}
<h2>What was not performed</h2>
<ul><li>No subnet or full-port scan</li><li>No brute force or credential attack</li><li>No SQLMap, unrestricted Nuclei, Metasploit, reverse shell, or persistence</li><li>No arbitrary model-generated command execution</li><li>No target or port expansion</li></ul>
<h2>Key distinction</h2>
<p><b>Replay mode</b> only explains existing evidence. <b>Live mode</b> starts a new authorized assessment and streams high-level events in the Terminal. Guided adaptive mode uses dynamic probe selection, but zero model calls means the prompts were selected from reviewed templates rather than invented by a model.</p>
</main></body></html>"""
    path.write_text(page, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--adaptive", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    data = {
        "baseline_run": args.baseline.name,
        "baseline_steps": plan_steps(args.baseline),
        "kali": kali_activity(args.baseline),
        "adaptive": adaptive_details(args.adaptive),
    }
    (args.output / "ATTACK_WALKTHROUGH.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(data, args.output / "ATTACK_WALKTHROUGH.md")
    write_html(data, args.output / "ATTACK_WALKTHROUGH.html")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
