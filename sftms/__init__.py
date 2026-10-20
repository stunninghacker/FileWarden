"""SFTMS - Secure File Transfer Monitoring System.

A blue-team / DLP toolkit that logs file movement, detects unauthorised
transfers of sensitive files, verifies file integrity via hashing, raises
alerts and produces an audit report.

The public entry point is :func:`sftms.cli.main`.
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = ["__version__", "Config", "load_config"]

from .config import Config, load_config  # noqa: E402  (import after __version__)
