"""Compatibility wrapper for report generation.

New scanner flows generate per-attack JSON reports and the combined Markdown
report from `scanner.attack_runner`. This module remains only for older imports.
"""

from scanner.attack_runner import generate_combined_report


def generate_report(_attack_name, results, _findings=None):
    scanned_targets = []
    seen = set()
    for result in results:
        target_name = result.get("target")
        if target_name and target_name not in seen:
            seen.add(target_name)
            scanned_targets.append({"name": target_name})
    return {"combined_report": str(generate_combined_report(results, scanned_targets))}
