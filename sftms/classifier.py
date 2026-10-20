"""Sensitivity classification of paths.

A path is considered *sensitive* when it either:

* lives underneath one of the configured ``sensitive_dirs``, or
* matches one of the ``sensitive_patterns`` globs (checked against both the
  basename and the full path, case-insensitively).
"""

from __future__ import annotations

import os
from fnmatch import fnmatch
from typing import Iterable, List, Optional, Tuple


def _norm(path: str) -> str:
    """Return an absolute, normalised, forward-slash, lower-cased path."""
    return os.path.normpath(os.path.abspath(path)).replace("\\", "/").lower()


class Classifier:
    """Decides whether a given path holds sensitive material."""

    def __init__(self, sensitive_dirs: Iterable[str] = (), sensitive_patterns: Iterable[str] = ()):
        self.sensitive_dirs: List[str] = [_norm(d) for d in sensitive_dirs if d]
        self.sensitive_patterns: List[str] = [str(p) for p in sensitive_patterns if p]

    # ------------------------------------------------------------------ #
    def _under_sensitive_dir(self, norm_path: str) -> Optional[str]:
        """Return the sensitive directory containing *norm_path*, if any."""
        for directory in self.sensitive_dirs:
            if norm_path == directory or norm_path.startswith(directory + "/"):
                return directory
        return None

    def _matches_pattern(self, norm_path: str) -> Optional[str]:
        """Return the sensitive pattern matching *norm_path*, if any."""
        base = os.path.basename(norm_path)
        for pattern in self.sensitive_patterns:
            pat = pattern.replace("\\", "/").lower()
            if fnmatch(base, pat) or fnmatch(norm_path, pat):
                return pattern
        return None

    # ------------------------------------------------------------------ #
    def match(self, path: Optional[str]) -> Optional[Tuple[str, str]]:
        """Return ``(kind, rule)`` describing why *path* is sensitive.

        ``kind`` is either ``"directory"`` or ``"pattern"``. Returns ``None``
        when the path is not sensitive.
        """
        if not path:
            return None
        norm = _norm(path)
        directory = self._under_sensitive_dir(norm)
        if directory:
            return ("directory", directory)
        pattern = self._matches_pattern(norm)
        if pattern:
            return ("pattern", pattern)
        return None

    def is_sensitive(self, path: Optional[str]) -> bool:
        """Return True if *path* is sensitive under any configured rule."""
        return self.match(path) is not None

    def explain(self, path: Optional[str]) -> str:
        """Return a human-readable reason string (used in alert details)."""
        result = self.match(path)
        if not result:
            return "not sensitive"
        kind, rule = result
        if kind == "directory":
            return f"inside sensitive directory '{rule}'"
        return f"filename/path matches sensitive pattern '{rule}'"
