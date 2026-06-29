from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TARGETS_DIR = PROJECT_ROOT / "targets"

def discover_targets():
    """
    Finds all Python targets under targets/ and returns a list of dicts.
    """
    targets = []
    if not TARGETS_DIR.exists():
        raise FileNotFoundError(f"Targets directory not found: {TARGETS_DIR}")

    for target_file in TARGETS_DIR.rglob("*.py"):
        if target_file.name.startswith("_"):
            continue
        targets.append({
            "name": target_file.stem,
            "path": str(target_file.relative_to(PROJECT_ROOT)),
            "absolute_path": str(target_file)
        })

    return targets

if __name__ == "__main__":
    discovered = discover_targets()
    if not discovered:
        print("No targets found.")
    else:
        print("Discovered targets:")
        for t in discovered:
            print(f"- {t['name']} -> {t['path']}")
