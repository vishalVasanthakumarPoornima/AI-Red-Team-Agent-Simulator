import json
from pathlib import Path
from datetime import datetime, timezone

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"

def generate_report(attack_name, results, findings):
    report = {
        "attack": attack_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "results": results,
        "analysis": findings
    }

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_file = REPORTS_DIR / f"{attack_name}_report.json"
    report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Report saved to {report_file}")
    return report
