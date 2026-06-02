import sys
from pathlib import Path
import json

# Add repo root to Python path so 'targets' and 'scanner' can be imported
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(REPO_ROOT))

# Imports
from targets.local_llm_agent.ollama_agent import ask_local_llm
from scanner.detectors import analyze_response
from scanner.report_generator import generate_report

# Paths
ATTACKS_DIR = REPO_ROOT / "attacks"
REPORTS_DIR = REPO_ROOT / "reports"

# Load payloads from attack folder
def load_payloads(attack_name):
    attack_path = ATTACKS_DIR / attack_name / "payloads.txt"
    if not attack_path.exists():
        raise FileNotFoundError(f"No payloads found for attack: {attack_name}")
    return [line.strip() for line in attack_path.read_text(encoding="utf-8").splitlines() if line.strip()]

# Run attack against local LLM target
def run_attack(attack_name):
    payloads = load_payloads(attack_name)
    results = []

    for payload in payloads:
        response = ask_local_llm(payload)
        results.append({"payload": payload, "response": response})

    return results

# Main block for testing
if __name__ == "__main__":
    attack = "system_prompt_disclosure"
    res = run_attack(attack)

    # Analyze each response
    all_findings = []
    for r in res:
        findings = analyze_response(r["response"])
        all_findings.append({"payload": r["payload"], "findings": findings})

    # Generate JSON report
    generate_report(attack, res, all_findings)