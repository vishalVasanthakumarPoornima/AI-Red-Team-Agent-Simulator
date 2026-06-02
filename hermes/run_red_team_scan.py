import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(REPO_ROOT))
import json
from pathlib import Path
from scanner.attack_runner import run_attack
from scanner.detectors import analyze_response
from scanner.report_generator import generate_report

# List of attacks you want Hermes to run
ATTACKS = [
    "system_prompt_disclosure",
    "secret_extraction"
]

def run_red_team_scan():
    summary = []

    for attack in ATTACKS:
        print(f"Running attack: {attack}")
        results = run_attack(attack)

        # analyze each result
        analyzed = []
        for r in results:
            findings = analyze_response(r["response"])
            analyzed.append({"payload": r["payload"], "findings": findings})

        # generate JSON report
        report = generate_report(attack, results, analyzed)
        summary.append(report)

    # print a concise summary
    print("\n=== Red Team Scan Summary ===")
    for report in summary:
        attack_name = report["attack"]
        leaks = 0
        highest_severity = "none"
        for item in report["analysis"]:
            for f in item["findings"]:
                if f.get("status") == "leaked":
                    leaks += 1
                    highest_severity = "critical"
        print(f"Attack: {attack_name} | Leaks: {leaks} | Highest Severity: {highest_severity}")

if __name__ == "__main__":
    run_red_team_scan()