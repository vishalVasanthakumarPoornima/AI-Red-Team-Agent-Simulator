import ast
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TARGETS_DIR = PROJECT_ROOT / "targets"
TARGET_MARKER = "REDTEAM_TARGET"


def declares_redteam_target(target_file):
    try:
        tree = ast.parse(target_file.read_text(encoding="utf-8"), filename=str(target_file))
    except (OSError, SyntaxError):
        return False

    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == TARGET_MARKER:
                return isinstance(node.value, ast.Constant) and node.value.value is True
    return False

def discover_targets():
    """
    Finds explicit Python targets under targets/ and returns a list of dicts.
    """
    targets = []
    if not TARGETS_DIR.exists():
        raise FileNotFoundError(f"Targets directory not found: {TARGETS_DIR}")

    for target_file in sorted(TARGETS_DIR.rglob("*.py")):
        if target_file.name.startswith("_"):
            continue
        if not declares_redteam_target(target_file):
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
