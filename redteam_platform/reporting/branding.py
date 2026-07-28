"""Branding validation with bounded local logo access."""

from __future__ import annotations

from pathlib import Path

from redteam_platform.reporting.models import Branding

ALLOWED_LOGO_SUFFIXES = {".png", ".jpg", ".jpeg", ".svg"}


def validate_branding(
    branding: Branding,
    *,
    permitted_logo_roots: list[str | Path] | None = None,
    maximum_logo_bytes: int = 1_000_000,
) -> Branding:
    if not branding.logo_path:
        return branding
    if branding.logo_path.startswith(("http://", "https://")):
        raise ValueError("Remote report logos are not allowed.")
    path = Path(branding.logo_path).expanduser().resolve()
    roots = [Path(item).expanduser().resolve() for item in (permitted_logo_roots or [])]
    if not roots or not any(path.is_relative_to(root) for root in roots):
        raise ValueError("Logo path is outside explicitly permitted roots.")
    if path.suffix.lower() not in ALLOWED_LOGO_SUFFIXES:
        raise ValueError("Logo must be PNG, JPEG, or SVG.")
    if not path.is_file() or path.is_symlink():
        raise ValueError("Logo must be a regular local file.")
    if path.stat().st_size > maximum_logo_bytes:
        raise ValueError("Logo exceeds the configured size limit.")
    return branding
