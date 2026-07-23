"""Compatibility wrapper for the modular :mod:`redteam_platform.cli` package.

The package directory takes precedence for imports and installed entry points.
This file remains so source checkouts and tooling that reference the historical
path have an explicit migration bridge.
"""

from redteam_platform.cli import app, main


if __name__ == "__main__":
    main()
