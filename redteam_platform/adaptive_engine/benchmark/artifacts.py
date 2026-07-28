"""Separate, atomic artifacts for model benchmarks."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from redteam_platform.artifacts import sanitize


class BenchmarkArtifacts:
    def __init__(self, root: str | Path, benchmark_id: str):
        self.benchmark_id = benchmark_id
        self.root = Path(root).expanduser()
        self.run_dir = self.root / benchmark_id
        self.run_dir.mkdir(parents=True, exist_ok=False, mode=0o700)

    def write_json(self, relative: str, value: Any) -> Path:
        if hasattr(value, "model_dump"):
            value = value.model_dump(mode="json")
        return self.write_text(
            relative, json.dumps(sanitize(value), indent=2, default=str) + "\n"
        )

    def write_text(self, relative: str, value: str) -> Path:
        path = self.run_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(str(sanitize(value)))
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()
        return path
