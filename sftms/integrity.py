"""File integrity: baseline creation, on-modify checks and full verification.

The baseline stores the SHA-256 (configurable) of every protected file. When a
baselined file is modified the monitor calls :meth:`IntegrityManager.check_modification`
which recomputes the hash and raises an ``INTEGRITY`` alert on mismatch.

:meth:`IntegrityManager.verify` performs a full scan and classifies every file
as ``intact`` / ``modified`` / ``deleted`` and reports ``added`` files found
under the protected directories but absent from the baseline.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .alerts import INTEGRITY, AlertManager
from .db import Database
from .hashing import file_size, hash_file


@dataclass
class VerifyResult:
    """Outcome of a full integrity verification."""

    intact: List[str] = field(default_factory=list)
    modified: List[str] = field(default_factory=list)
    deleted: List[str] = field(default_factory=list)
    added: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    algorithm: str = "sha256"

    @property
    def total(self) -> int:
        """Total number of files considered."""
        return len(self.intact) + len(self.modified) + len(self.deleted) + len(self.added)


class IntegrityManager:
    """Creates, verifies and monitors a hash baseline of protected files."""

    def __init__(
        self,
        db: Database,
        algorithm: str = "sha256",
        alerts: Optional[AlertManager] = None,
        protected_dirs=(),
        alert_cooldown_seconds: int = 3,
    ):
        self.db = db
        self.algorithm = algorithm
        self.alerts = alerts
        self.protected_dirs = [os.path.abspath(d) for d in protected_dirs if d]
        self.alert_cooldown_seconds = alert_cooldown_seconds
        self._recent_alerts: Dict[str, float] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Baseline
    # ------------------------------------------------------------------ #
    def _iter_files(self, directory: str):
        """Yield every file beneath *directory*, ignoring symlinked dirs."""
        for root, _dirs, files in os.walk(directory):
            for name in files:
                yield os.path.join(root, name)

    def create_baseline(self, directory: str, recursive: bool = True) -> Dict[str, object]:
        """Hash every file under *directory* and (re)store it in the baseline.

        Returns a summary dict with ``directory``, ``algorithm`` and ``files``.
        """
        directory = os.path.abspath(directory)
        if not os.path.isdir(directory):
            raise NotADirectoryError(f"Not a directory: {directory}")
        if directory not in self.protected_dirs:
            self.protected_dirs.append(directory)

        count = 0
        for path in self._iter_files(directory):
            digest = hash_file(path, self.algorithm)
            if digest is None:
                continue
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                mtime = None
            self.db.upsert_baseline(
                path=os.path.abspath(path),
                algorithm=self.algorithm,
                digest=digest,
                size=file_size(path),
                mtime=mtime,
            )
            count += 1
        return {"directory": directory, "algorithm": self.algorithm, "files": count}

    # ------------------------------------------------------------------ #
    # On-modify tamper detection
    # ------------------------------------------------------------------ #
    def check_modification(self, path: str) -> Optional[str]:
        """Recompute the hash of a baselined *path*; alert on mismatch.

        Returns the new digest when a mismatch was detected, else ``None``.
        """
        path = os.path.abspath(path)
        row = self.db.get_baseline(path)
        if row is None:
            return None

        current = hash_file(path, self.algorithm)
        if current is None:
            return None  # deleted or unreadable - handled by verify/delete flows

        try:
            self.db.update_current_hash(path, current)
        except Exception:  # pragma: no cover
            pass

        if current == row["baseline_hash"]:
            return None

        now = time.monotonic()
        with self._lock:
            last = self._recent_alerts.get(path, 0.0)
            if now - last < self.alert_cooldown_seconds:
                return current
            self._recent_alerts[path] = now

        if self.alerts is not None:
            self.alerts.emit(
                severity=INTEGRITY,
                title="Integrity violation: file modified",
                detail=(
                    f"{os.path.basename(path)} hash changed "
                    f"(baseline {row['baseline_hash'][:12]}... != current {current[:12]}...)"
                ),
                src_path=path,
            )
        return current

    # ------------------------------------------------------------------ #
    # Full verification
    # ------------------------------------------------------------------ #
    def verify(self, emit_alerts: bool = True) -> VerifyResult:
        """Compare every baselined file against its stored hash.

        Also reports files that appeared under the protected directories since
        the baseline was taken (``added``). Set *emit_alerts* to ``False`` for
        read-only verification (e.g. when building a report) to avoid raising
        duplicate alerts.
        """
        result = VerifyResult(algorithm=self.algorithm)
        rows = self.db.all_baselines()
        baselined = set()

        for row in rows:
            path = row["path"]
            baselined.add(os.path.normcase(path))
            if not os.path.isfile(path):
                result.deleted.append(path)
                continue
            current = hash_file(path, self.algorithm)
            if current is None:
                result.errors.append(path)
                continue
            try:
                self.db.update_current_hash(path, current)
            except Exception:  # pragma: no cover
                pass
            if current == row["baseline_hash"]:
                result.intact.append(path)
            else:
                result.modified.append(path)

        # Detect newly-added files under the protected directories.
        seen_added = set()
        for directory in self.protected_dirs:
            if not os.path.isdir(directory):
                continue
            for path in self._iter_files(directory):
                norm = os.path.normcase(os.path.abspath(path))
                if norm not in baselined and norm not in seen_added:
                    seen_added.add(norm)
                    result.added.append(os.path.abspath(path))

        if self.alerts is not None and emit_alerts:
            for path in result.modified:
                self.alerts.emit(
                    severity=INTEGRITY,
                    title="Integrity violation found during verify",
                    detail=f"{os.path.basename(path)} differs from the baseline",
                    src_path=path,
                )
            for path in result.deleted:
                self.alerts.emit(
                    severity=INTEGRITY,
                    title="Baselined file missing",
                    detail=f"{os.path.basename(path)} is in the baseline but no longer exists",
                    src_path=path,
                )
        return result
