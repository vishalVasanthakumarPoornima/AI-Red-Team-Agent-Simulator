"""Natural-language assistant for the local AI red-team simulator."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
import re
from pathlib import Path

from assessment_monitor import AssessmentMonitor
from agent_registry import discover_local_agents, local_discovery_ports
from enterprise_report import write_enterprise_report
from http_agent_attack import run_http_agent_attack
from kali_agent_attack import run_kali_agent_attack
from local_red_team.run_local_red_team_scan import run_scan as run_local_red_team_scan
from scanner.attack_runner import run_all_attacks, status_counts
from scanner.target_loader import discover_targets


HELP_TEXT = """I can understand requests like:
- find active agents on this machine
- show me the repo targets
- attack all local targets and generate an enterprise report
- attack active running agents
- run a comprehensive dynamic demo assessment with Kali
- run adaptive local red team against travel_agent
- run the ThinkPad Kali assessment
- full assessment with Kali and enterprise report

The assistant stays scoped to local/authorized targets configured in this repo.
"""

DEFAULT_KALI_KEY = "~/.ssh/kali_ai_red_team"


@dataclass
class AssistantIntent:
    action: str
    target: str | None = None
    attack: str | None = None
    include_kali: bool = False
    include_adaptive: bool = False
    enterprise_report: bool = False
    max_payloads: int = 2
    raw_text: str = ""
    notes: list[str] = field(default_factory=list)


def _known_target_names():
    try:
        return sorted(target["name"] for target in discover_targets())
    except Exception:
        return []


def _selected_targets(target_name=None):
    targets = discover_targets()
    if not target_name:
        return targets
    return [target for target in targets if target["name"] == target_name]


def _extract_target(text):
    lowered = text.lower()
    for name in _known_target_names():
        if name.lower() in lowered:
            return name
    return None


def _extract_attack(text):
    lowered = text.lower()
    for attack in (
        "prompt_disclosure",
        "system_prompt_disclosure",
        "prompt_injection",
        "tool_abuse",
        "secret_extraction",
    ):
        if attack in lowered or attack.replace("_", " ") in lowered:
            return attack
    return None


def _extract_max_payloads(text, default=2):
    match = re.search(r"\b(?:max payloads|payloads|prompts)\s*(?:=|:)?\s*(\d+)\b", text, re.I)
    if not match:
        match = re.search(r"\b(\d+)\s*(?:payloads|prompts)\b", text, re.I)
    if not match:
        return default
    return max(1, min(int(match.group(1)), 10))


def _heuristic_interpret(text):
    lowered = " ".join(text.lower().split())
    target = _extract_target(text)
    attack = _extract_attack(text)
    comprehensive = any(word in lowered for word in ("comprehensive", "demo", "showcase"))
    include_kali = any(
        word in lowered
        for word in ("kali", "thinkpad", "nmap", "nikto", "whatweb")
    ) or comprehensive
    include_adaptive = any(
        phrase in lowered
        for phrase in (
            "adaptive",
            "dynamic",
            "get to know",
            "getting to know",
            "local red team",
            "local model",
            "use local model",
            "ollama planner",
        )
    ) or comprehensive
    enterprise = any(word in lowered for word in ("enterprise", "report", "findings", "risk register"))
    max_payloads = _extract_max_payloads(text)

    if lowered in {"q", "quit", "exit", "stop"}:
        action = "quit"
    elif any(word in lowered for word in ("help", "what can you do", "commands")):
        action = "help"
    elif "target" in lowered and not any(word in lowered for word in ("attack", "scan", "test")):
        action = "list_targets"
    elif any(phrase in lowered for phrase in ("active agents", "running agents", "http agents")) and any(
        word in lowered for word in ("attack", "assess", "scan", "test")
    ):
        action = "attack_active_agents"
    elif any(phrase in lowered for phrase in ("find active", "discover active", "running agents", "same machine")):
        action = "discover_agents"
    elif any(
        phrase in lowered
        for phrase in (
            "master",
            "full assessment",
            "comprehensive",
            "demo assessment",
            "dynamic assessment",
            "attack all",
            "assess all",
            "test everything",
        )
    ):
        action = "master_assessment"
        enterprise = True
    elif include_kali and any(word in lowered for word in ("status", "reachable", "ready", "check")):
        action = "kali_status"
    elif include_kali and any(word in lowered for word in ("attack", "assess", "scan", "test")):
        action = "kali_attack"
    elif include_adaptive:
        action = "local_red_team"
    elif any(word in lowered for word in ("attack", "scan", "test", "assess")):
        action = "static_scan"
    else:
        action = "help"

    return AssistantIntent(
        action=action,
        target=target,
        attack=attack,
        include_kali=include_kali,
        include_adaptive=include_adaptive,
        enterprise_report=enterprise,
        max_payloads=max_payloads,
        raw_text=text,
    )


def _local_model_interpret(text):
    model = os.environ.get("REDTEAM_NL_MODEL")
    if not model:
        return None
    from targets.local_llm_agent.ollama_agent import generate_with_ollama

    system_prompt = """
You convert user requests into JSON for a local authorized AI red-team CLI.
Allowed action values: help, quit, list_targets, discover_agents, static_scan,
attack_active_agents, local_red_team, kali_status, kali_attack, master_assessment.
Return JSON only. Do not add explanations.
""".strip()
    prompt = f"""
Known target names: {', '.join(_known_target_names())}
User request: {text}

Return:
{{
  "action": "...",
  "target": null,
  "attack": null,
  "include_kali": false,
  "include_adaptive": false,
  "enterprise_report": false,
  "max_payloads": 2
}}
""".strip()
    response = generate_with_ollama(prompt, system_prompt=system_prompt, model=model)
    if str(response).startswith("ERROR:"):
        return None
    try:
        parsed = json.loads(str(response).strip())
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict) or not parsed.get("action"):
        return None
    return AssistantIntent(
        action=str(parsed.get("action")),
        target=parsed.get("target"),
        attack=parsed.get("attack"),
        include_kali=bool(parsed.get("include_kali")),
        include_adaptive=bool(parsed.get("include_adaptive")),
        enterprise_report=bool(parsed.get("enterprise_report")),
        max_payloads=max(1, min(int(parsed.get("max_payloads") or 2), 10)),
        raw_text=text,
        notes=["interpreted_by_local_model"],
    )


def interpret_request(text, prefer_local_model=False):
    if prefer_local_model:
        interpreted = _local_model_interpret(text)
        if interpreted:
            return interpreted
    return _heuristic_interpret(text)


def _active_agents(timeout=0.35):
    ports = local_discovery_ports("18080,18101-18110")
    return discover_local_agents("127.0.0.1", ports=ports, timeout=timeout)


def _identity_file():
    configured = os.environ.get("KALI_SSH_KEY")
    if configured:
        return configured
    default_path = Path(DEFAULT_KALI_KEY).expanduser()
    if default_path.exists():
        return DEFAULT_KALI_KEY
    return None


def _scan_summary(run_result):
    counts = status_counts(run_result["results"])
    return {
        "tests": len(run_result["results"]),
        "pass": counts["PASS"],
        "fail": counts["FAIL"],
        "error": counts["ERROR"],
        "combined_report": str(run_result["combined_report"]),
    }


def _print_summary_line(say, label, summary):
    say(
        f"{label}: {summary.get('pass', 0)} PASS, {summary.get('fail', 0)} FAIL, "
        f"{summary.get('error', 0)} ERROR"
        + (f", {summary.get('unparsed')} UNPARSED" if "unparsed" in summary else "")
    )


def _agent_summary(agents):
    return [
        {
            "name": agent.get("name"),
            "kind": agent.get("kind"),
            "status": agent.get("status"),
            "base_url": agent.get("base_url"),
            "targets": agent.get("targets") or [],
        }
        for agent in agents
    ]


def _target_summary(targets):
    return [
        {
            "name": target.get("name"),
            "path": target.get("path"),
        }
        for target in targets
    ]


def _finalize_monitor(assessment, monitor):
    artifacts = monitor.write()
    assessment["monitoring"] = artifacts
    return artifacts


def execute_intent(intent, say=print, kali_host=None):
    monitor = AssessmentMonitor(request=intent.raw_text, intent=intent.__dict__)
    monitor.event(
        "intent",
        "interpreted",
        status="ok",
        details={
            "action": intent.action,
            "target": intent.target,
            "attack": intent.attack,
            "include_kali": intent.include_kali,
            "include_adaptive": intent.include_adaptive,
            "enterprise_report": intent.enterprise_report,
            "max_payloads": intent.max_payloads,
            "notes": intent.notes,
        },
    )
    assessment = {
        "request": intent.raw_text,
        "intent": intent.__dict__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets": _selected_targets(intent.target),
        "active_agents": [],
        "runs": {},
    }

    if intent.action == "quit":
        monitor.event("assistant", "quit", status="ok")
        return {"done": True, "message": "Exiting."}
    if intent.action == "help":
        monitor.event("assistant", "help_displayed", status="ok")
        say(HELP_TEXT)
        return {"message": HELP_TEXT}
    if intent.action == "list_targets":
        targets = discover_targets()
        monitor.event(
            "target_discovery",
            "repository_targets_listed",
            status="ok",
            details={"targets": _target_summary(targets)},
        )
        assessment["targets"] = targets
        _finalize_monitor(assessment, monitor)
        for target in targets:
            say(f"- {target['name']}: {target['path']}")
        return {"targets": targets}
    if intent.action == "discover_agents":
        monitor.event(
            "agent_discovery",
            "active_agent_discovery_started",
            status="running",
            details={"host": "127.0.0.1", "ports": "18080,18101-18110"},
        )
        agents = _active_agents()
        assessment["active_agents"] = agents
        monitor.event(
            "agent_discovery",
            "active_agent_discovery_completed",
            status="ok",
            details={"agents": _agent_summary(agents), "count": len(agents)},
        )
        artifacts = _finalize_monitor(assessment, monitor)
        if not agents:
            say("No active compatible local agents found.")
        for agent in agents:
            target_text = ", ".join(agent.get("targets") or [])
            suffix = f" targets={target_text}" if target_text else ""
            say(f"- {agent['name']} ({agent['kind']}) {agent['base_url']}{suffix}")
        say(f"Assessment timeline: {artifacts['timeline_markdown']}")
        return assessment

    if intent.action == "static_scan":
        say("Running static payload scan against repository targets...")
        monitor.event(
            "static_scan",
            "started",
            status="running",
            details={
                "target": intent.target,
                "attack": intent.attack,
                "targets": _target_summary(assessment["targets"]),
            },
        )
        scan = run_all_attacks(target_name=intent.target, attack_name=intent.attack)
        summary = _scan_summary(scan)
        assessment["runs"]["static_scan"] = {
            "summary": summary,
            "results": scan["results"],
            "combined_report": str(scan["combined_report"]),
        }
        monitor.event("static_scan", "completed", status="ok", details=summary)
        _print_summary_line(say, "Static scan", summary)

    elif intent.action == "attack_active_agents":
        say("Discovering active compatible local agents, running reconnaissance, and generating dynamic probes...")
        monitor.event(
            "agent_discovery",
            "active_agent_discovery_started",
            status="running",
            details={"host": "127.0.0.1", "ports": "18080,18101-18110"},
        )
        agents = _active_agents(timeout=1)
        assessment["active_agents"] = agents
        monitor.event(
            "agent_discovery",
            "active_agent_discovery_completed",
            status="ok",
            details={"agents": _agent_summary(agents), "count": len(agents)},
        )
        monitor.event(
            "http_agent_scan",
            "started",
            status="running",
            details={"agent_count": len(agents), "include_static": True, "include_dynamic": True},
        )
        http_report = run_http_agent_attack(agents, monitor=monitor)
        assessment["runs"]["http_agent_scan"] = http_report
        monitor.event("http_agent_scan", "completed", status="ok", details=http_report["summary"])
        _print_summary_line(say, "HTTP agent scan", http_report["summary"])

    elif intent.action == "local_red_team":
        say("Running adaptive local red-team scan...")
        monitor.event(
            "local_red_team",
            "started",
            status="running",
            details={"target": intent.target, "max_payloads": intent.max_payloads},
        )
        local_report = run_local_red_team_scan(
            selected_target=intent.target,
            max_payloads=intent.max_payloads,
        )
        assessment["runs"]["local_red_team"] = local_report
        monitor.event("local_red_team", "completed", status="ok", details=local_report["summary"])
        _print_summary_line(say, "Local red-team", local_report["summary"])

    elif intent.action == "kali_status":
        monitor.event("kali_status", "not_executed", status="info")
        say("Kali status is available through the CLI status path. Ask me to run the Kali assessment to execute probes.")

    elif intent.action == "kali_attack":
        say("Running ThinkPad/Kali-backed agent assessment...")
        monitor.event(
            "kali_agent_scan",
            "started",
            status="running",
            details={"host": kali_host or os.environ.get("KALI_SSH_HOST", "kali-redteam")},
        )
        kali_report = run_kali_agent_attack(
            host=kali_host or os.environ.get("KALI_SSH_HOST", "kali-redteam"),
            identity_file=_identity_file(),
            ollama_model=os.environ.get("OLLAMA_MODEL"),
            ollama_timeout=int(os.environ.get("OLLAMA_TIMEOUT_SECONDS", "180")),
            report_path="reports/kali_agent_scan.json",
            monitor=monitor,
        )
        assessment["runs"]["kali_agent_scan"] = kali_report
        monitor.event("kali_agent_scan", "assistant_completed", status="ok", details=kali_report["summary"])
        _print_summary_line(say, "Kali agent scan", kali_report["summary"])

    elif intent.action == "master_assessment":
        say("Running master assessment: discovery, repo-target scan, dynamic active-agent scan, and report generation.")
        monitor.event(
            "agent_discovery",
            "active_agent_discovery_started",
            status="running",
            details={"host": "127.0.0.1", "ports": "18080,18101-18110"},
        )
        agents = _active_agents(timeout=1)
        assessment["active_agents"] = agents
        monitor.event(
            "agent_discovery",
            "active_agent_discovery_completed",
            status="ok",
            details={"agents": _agent_summary(agents), "count": len(agents)},
        )

        monitor.event(
            "static_scan",
            "started",
            status="running",
            details={
                "target": intent.target,
                "attack": intent.attack,
                "targets": _target_summary(assessment["targets"]),
            },
        )
        scan = run_all_attacks(target_name=intent.target, attack_name=intent.attack)
        summary = _scan_summary(scan)
        assessment["runs"]["static_scan"] = {
            "summary": summary,
            "results": scan["results"],
            "combined_report": str(scan["combined_report"]),
        }
        monitor.event("static_scan", "completed", status="ok", details=summary)
        _print_summary_line(say, "Static scan", summary)

        if agents:
            monitor.event(
                "http_agent_scan",
                "started",
                status="running",
                details={"agent_count": len(agents), "include_static": True, "include_dynamic": True},
            )
            http_report = run_http_agent_attack(agents, monitor=monitor)
            assessment["runs"]["http_agent_scan"] = http_report
            monitor.event("http_agent_scan", "completed", status="ok", details=http_report["summary"])
            _print_summary_line(say, "HTTP agent scan", http_report["summary"])
        else:
            monitor.event("http_agent_scan", "skipped_no_agents", status="info")
            say("No active compatible local agents were running; skipped HTTP service attack.")

        if intent.include_adaptive:
            monitor.event(
                "local_red_team",
                "started",
                status="running",
                details={"target": intent.target, "max_payloads": intent.max_payloads},
            )
            local_report = run_local_red_team_scan(
                selected_target=intent.target,
                max_payloads=intent.max_payloads,
            )
            assessment["runs"]["local_red_team"] = local_report
            monitor.event("local_red_team", "completed", status="ok", details=local_report["summary"])
            _print_summary_line(say, "Local red-team", local_report["summary"])

        if intent.include_kali:
            monitor.event(
                "kali_agent_scan",
                "started",
                status="running",
                details={"host": kali_host or os.environ.get("KALI_SSH_HOST", "kali-redteam")},
            )
            kali_report = run_kali_agent_attack(
                host=kali_host or os.environ.get("KALI_SSH_HOST", "kali-redteam"),
                identity_file=_identity_file(),
                ollama_model=os.environ.get("OLLAMA_MODEL"),
                ollama_timeout=int(os.environ.get("OLLAMA_TIMEOUT_SECONDS", "180")),
                report_path="reports/kali_agent_scan.json",
                monitor=monitor,
            )
            assessment["runs"]["kali_agent_scan"] = kali_report
            monitor.event("kali_agent_scan", "assistant_completed", status="ok", details=kali_report["summary"])
            _print_summary_line(say, "Kali agent scan", kali_report["summary"])

    else:
        monitor.event("assistant", "fallback_help_displayed", status="info")
        say(HELP_TEXT)
        return {"message": HELP_TEXT}

    if intent.enterprise_report or intent.action == "master_assessment":
        monitor.event("reporting", "enterprise_report_started", status="running")
        _finalize_monitor(assessment, monitor)
        report = write_enterprise_report(assessment)
        assessment["enterprise_report"] = report
        monitor.event("reporting", "enterprise_report_written", status="ok", details=report)
        artifacts = _finalize_monitor(assessment, monitor)
        report = write_enterprise_report(assessment)
        assessment["enterprise_report"] = report
        say(f"Enterprise report: {report['markdown_report']}")
        say(f"Report JSON: {report['json_report']}")
        say(f"Assessment timeline: {artifacts['timeline_markdown']}")
        say(f"Assessment events: {artifacts['events_jsonl']}")
    else:
        monitor.event("assessment", "completed", status="ok")
        artifacts = _finalize_monitor(assessment, monitor)
        say(f"Assessment timeline: {artifacts['timeline_markdown']}")

    return assessment


def run_chat(message=None, prefer_local_model=False, kali_host=None):
    if message:
        intent = interpret_request(message, prefer_local_model=prefer_local_model)
        return execute_intent(intent, kali_host=kali_host)

    print("Natural-language AI Red Team Assistant")
    print("Type 'help' for examples or 'quit' to exit.")
    while True:
        try:
            text = input("redteam> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return {"done": True}
        if not text:
            continue
        intent = interpret_request(text, prefer_local_model=prefer_local_model)
        result = execute_intent(intent, kali_host=kali_host)
        if result.get("done"):
            print(result.get("message", "Done."))
            return result
