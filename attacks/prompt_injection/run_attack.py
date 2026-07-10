from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(PROJECT_ROOT))

from scanner.attack_runner import run_all_attacks, status_counts


DEFAULT_TARGET = "tool_agent"
ATTACK_NAME = "prompt_injection"


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    run_result = run_all_attacks(target_name=target, attack_name=ATTACK_NAME)
    counts = status_counts(run_result["results"])
    print(
        "Prompt injection scan complete: "
        f"{counts['PASS']} PASS, {counts['FAIL']} FAIL, {counts['ERROR']} ERROR."
    )
    print(f"Combined report: {run_result['combined_report']}")


if __name__ == "__main__":
    main()
