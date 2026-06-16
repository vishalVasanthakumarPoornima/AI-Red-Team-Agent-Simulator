import argparse
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

from scanner.detectors import SEVERITY_ORDER, evaluate_response
from scanner.target_loader import discover_targets


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ATTACKS_DIR = PROJECT_ROOT / "attacks"
REPORTS_DIR = PROJECT_ROOT / "reports"
DEFAULT_ATTACKS = (
    "prompt_disclosure",
    "system_prompt_disclosure",
    "prompt_injection",
    "tool_abuse",
    "secret_extraction",
)
RESPONSE_EXCERPT_LIMIT = 500


def load_payloads(attack_name):
    payload_path = ATTACKS_DIR / attack_name / "payloads.txt"
    if not payload_path.exists():
        raise FileNotFoundError(f"Payload file not found: {payload_path}")

    payloads = []
    for line in payload_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            payloads.append(stripped)

    if not payloads:
        raise ValueError(f"No payloads found in {payload_path}")

    return payloads


def load_attacks(selected_attack=None):
    attack_names = [selected_attack] if selected_attack else list(DEFAULT_ATTACKS)
    return [{"name": name, "prompts": load_payloads(name)} for name in attack_names]


def filter_targets(targets, selected_target=None):
    if not selected_target:
        return targets

    selected = [target for target in targets if target["name"] == selected_target]
    if not selected:
        available = ", ".join(sorted(target["name"] for target in targets)) or "none"
        raise ValueError(f"Target '{selected_target}' not found. Available targets: {available}")

    return selected


def import_target_module(target):
    target_path = Path(target["absolute_path"])
    module_name = f"redteam_target_{target['name']}"
    spec = importlib.util.spec_from_file_location(module_name, target_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load target module from {target_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def looks_like_error_response(response_text):
    lowered = str(response_text or "").strip().lower()
    return lowered.startswith(("error:", "error executing", "ollama error:"))


def error_result(target, attack_name, prompt, response_text, reason):
    return {
        "target": target["name"],
        "attack": attack_name,
        "prompt": prompt,
        "response": str(response_text),
        "status": "ERROR",
        "passed": False,
        "severity": "Error",
        "confidence": 1.0,
        "reason": reason,
        "detectors": [],
        "evidence": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def run_prompt_against_target(target, attack_name, prompt):
    try:
        module = import_target_module(target)
        if not hasattr(module, "run_agent"):
            return error_result(
                target,
                attack_name,
                prompt,
                "",
                "Target does not expose a run_agent(prompt) function.",
            )

        response_text = module.run_agent(prompt)
        if response_text is None:
            response_text = ""
        if not isinstance(response_text, str):
            response_text = json.dumps(response_text, indent=2, default=str)

        if looks_like_error_response(response_text):
            return error_result(target, attack_name, prompt, response_text, response_text)

        evaluation = evaluate_response(prompt, response_text, attack_name)
        return {
            "target": target["name"],
            "attack": attack_name,
            "prompt": prompt,
            "response": response_text,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **evaluation,
        }
    except Exception as exc:
        return error_result(target, attack_name, prompt, "", f"Error executing target: {exc}")


def run_attack(target, attack):
    return [
        run_prompt_against_target(target, attack["name"], prompt)
        for prompt in attack["prompts"]
    ]


def save_attack_report(target, attack_name, results):
    target_dir = REPORTS_DIR / target["name"]
    target_dir.mkdir(parents=True, exist_ok=True)
    report_path = target_dir / f"{attack_name}.json"
    report_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return report_path


def status_counts(results):
    return {
        "PASS": sum(1 for result in results if result["status"] == "PASS"),
        "FAIL": sum(1 for result in results if result["status"] == "FAIL"),
        "ERROR": sum(1 for result in results if result["status"] == "ERROR"),
    }


def failure_rate(results):
    if not results:
        return 0.0
    failures = sum(1 for result in results if result["status"] == "FAIL")
    return failures / len(results)


def highest_severity(results):
    if not results:
        return "Informational"
    return max((result["severity"] for result in results), key=SEVERITY_ORDER.index)


def truncate_text(value, limit=RESPONSE_EXCERPT_LIMIT):
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def fenced_text(value):
    return str(value or "").replace("```", "'''")


def generate_combined_report(all_results, scanned_targets):
    combined_path = REPORTS_DIR / "combined_report.md"
    total_tests = len(all_results)
    failures = sum(1 for result in all_results if result["status"] == "FAIL")
    errors = sum(1 for result in all_results if result["status"] == "ERROR")
    fail_rate = failure_rate(all_results) * 100

    lines = [
        "# AI Agent Red Team Scan",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Executive Summary",
        "",
        f"- Total targets scanned: {len(scanned_targets)}",
        f"- Total tests run: {total_tests}",
        f"- Total failures: {failures}",
        f"- Total errors: {errors}",
        f"- Failure rate: {fail_rate:.1f}%",
        "",
        "## Per-Target Summary",
        "",
        "| Target | Tests | PASS | FAIL | ERROR | Failure Rate | Highest Severity |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]

    for target in scanned_targets:
        target_results = [result for result in all_results if result["target"] == target["name"]]
        counts = status_counts(target_results)
        lines.append(
            f"| {target['name']} | {len(target_results)} | {counts['PASS']} | {counts['FAIL']} | "
            f"{counts['ERROR']} | {failure_rate(target_results) * 100:.1f}% | "
            f"{highest_severity(target_results)} |"
        )

    attack_names = sorted({result["attack"] for result in all_results})
    lines.extend(
        [
            "",
            "## Per-Attack Summary",
            "",
            "| Attack | Tests | PASS | FAIL | ERROR | Failure Rate | Highest Severity |",
            "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
        ]
    )

    for attack_name in attack_names:
        attack_results = [result for result in all_results if result["attack"] == attack_name]
        counts = status_counts(attack_results)
        lines.append(
            f"| {attack_name} | {len(attack_results)} | {counts['PASS']} | {counts['FAIL']} | "
            f"{counts['ERROR']} | {failure_rate(attack_results) * 100:.1f}% | "
            f"{highest_severity(attack_results)} |"
        )

    lines.extend(["", "## Individual Test Details", ""])

    for result in all_results:
        lines.extend(
            [
                f"### {result['target']} / {result['attack']} / {result['status']}",
                "",
                f"- Severity: {result['severity']}",
                f"- Confidence: {result['confidence']}",
                f"- Reason: {result['reason']}",
                "",
                "Prompt:",
                "",
                "```text",
                fenced_text(result["prompt"]),
                "```",
                "",
                "Response excerpt:",
                "",
                "```text",
                fenced_text(truncate_text(result["response"])),
                "```",
                "",
            ]
        )

    combined_path.write_text("\n".join(lines), encoding="utf-8")
    return combined_path


def run_all_attacks(target_name=None, attack_name=None):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    targets = filter_targets(discover_targets(), target_name)
    attacks = load_attacks(attack_name)
    all_results = []

    for target in targets:
        for attack in attacks:
            results = run_attack(target, attack)
            all_results.extend(results)
            save_attack_report(target, attack["name"], results)

    combined_report = generate_combined_report(all_results, targets)
    return {"results": all_results, "combined_report": combined_report}


def parse_args():
    parser = argparse.ArgumentParser(description="Run local AI agent red-team payloads.")
    parser.add_argument("--target", help="Target module name to scan, for example: ollama_agent")
    parser.add_argument("--attack", help="Attack name to run, for example: prompt_disclosure")
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        run_result = run_all_attacks(target_name=args.target, attack_name=args.attack)
    except (FileNotFoundError, ValueError) as exc:
        raise SystemExit(f"ERROR: {exc}") from exc

    counts = status_counts(run_result["results"])
    print(
        "Scan complete: "
        f"{counts['PASS']} PASS, {counts['FAIL']} FAIL, {counts['ERROR']} ERROR. "
        f"Combined report: {run_result['combined_report']}"
    )


if __name__ == "__main__":
    main()
