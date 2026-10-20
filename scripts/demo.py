"""Standalone demo launcher.

Run either of::

    python scripts/demo.py
    sftms demo            # after `pip install -e .`
    python -m sftms demo

This wraps :func:`sftms.demo.run_demo`; the heavy lifting lives in the package
so the CLI and this script share one implementation.
"""

from __future__ import annotations

import os
import sys

# Make the sibling `sftms` package importable when run as a plain script.
_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_DIR not in sys.path:
    sys.path.insert(0, _PROJECT_DIR)

from sftms.demo import run_demo  # noqa: E402  (import after sys.path tweak)


def main() -> None:
    """Run the demo scenario."""
    run_demo()


if __name__ == "__main__":
    main()
