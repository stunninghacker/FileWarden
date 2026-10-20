"""Authorisation / suspicion logic.

Given an :class:`~sftms.db.Event` this module decides whether the movement is
acceptable or suspicious:

* sensitive file touching only local storage        -> LOW
* sensitive file copied/moved to USB / network / cloud -> HIGH
* more than ``bulk_threshold`` sensitive-or-external events targeting the same
  destination inside ``bulk_window_seconds``        -> CRITICAL (exfiltration)

The :class:`Authorizer` keeps rolling state (deques of event times) so the bulk
detector can work across calls; call :meth:`Authorizer.reset` between runs.
"""

from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum
from typing import Deque, Dict, List, Optional

from .alerts import CRITICAL, HIGH, LOW
from .classifier import Classifier
from .detectors import DriveClass, classify_destination


class Decision(str, Enum):
    """Outcome of evaluating a single event."""

    ALLOWED = "allowed"
    SENSITIVE_LOCAL = "sensitive_local"
    SENSITIVE_EXTERNAL = "sensitive_external"
    BULK_EXFILTRATION = "bulk_exfiltration"


@dataclass
class AuthorizationResult:
    """The authorizer's verdict for an event."""

    decision: Decision
    severity: Optional[str]
    reason: str
    dest_class: DriveClass

    @property
    def is_alert(self) -> bool:
        """True when the result should raise an alert."""
        return self.severity is not None


def _destination_root(path: Optional[str]) -> str:
    """Group key for bulk detection: the directory holding the destination."""
    if not path:
        return "unknown"
    return os.path.normcase(os.path.dirname(os.path.abspath(path)))


class Authorizer:
    """Evaluates events and maintains rolling state for bulk detection."""

    def __init__(
        self,
        classifier: Classifier,
        cloud_patterns=(),
        removable_patterns=(),
        network_patterns=(),
        bulk_threshold: int = 50,
        bulk_window_seconds: int = 60,
    ):
        self.classifier = classifier
        self.cloud_patterns = list(cloud_patterns)
        self.removable_patterns = list(removable_patterns)
        self.network_patterns = list(network_patterns)
        self.bulk_threshold = bulk_threshold
        self.bulk_window_seconds = bulk_window_seconds
        # Rolling counters keyed by destination root.
        self._recent: Dict[str, Deque[float]] = defaultdict(deque)
        self._bulk_last_fired: Dict[str, float] = {}

    # ------------------------------------------------------------------ #
    def reset(self) -> None:
        """Clear all rolling bulk-detection state."""
        self._recent.clear()
        self._bulk_last_fired.clear()

    # ------------------------------------------------------------------ #
    def classify_dest(self, path: Optional[str]) -> DriveClass:
        """Classify a destination path using the configured pattern sets."""
        return classify_destination(
            path,
            cloud_patterns=self.cloud_patterns,
            removable_patterns=self.removable_patterns,
            network_patterns=self.network_patterns,
        )

    # ------------------------------------------------------------------ #
    def _bulk_check(self, key: str, now: float) -> Optional[AuthorizationResult]:
        """Update the rolling window for *key* and return a BULK result if hit."""
        window = self.bulk_window_seconds
        bucket = self._recent[key]
        bucket.append(now)
        cutoff = now - window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        if len(bucket) < self.bulk_threshold:
            return None

        # Cooldown: fire at most once per window per destination.
        last = self._bulk_last_fired.get(key, 0.0)
        if now - last < window:
            return None
        self._bulk_last_fired[key] = now
        return AuthorizationResult(
            decision=Decision.BULK_EXFILTRATION,
            severity=CRITICAL,
            reason=(
                f"{len(bucket)} file events targeting '{key}' within "
                f"{window}s (threshold {self.bulk_threshold}) - possible exfiltration"
            ),
            dest_class=DriveClass.UNKNOWN,
        )

    # ------------------------------------------------------------------ #
    def evaluate(self, event) -> List[AuthorizationResult]:
        """Evaluate *event* and return every result it triggers.

        The event is expected to already carry ``is_sensitive`` and
        ``dest_class`` (set by the monitor), but both are recomputed here so the
        method is safe to call standalone (e.g. from tests).
        """
        results: List[AuthorizationResult] = []

        dest_class = self.classify_dest(event.dest_path)
        if dest_class is DriveClass.UNKNOWN:
            # No destination (e.g. delete) - reuse what the monitor computed.
            try:
                dest_class = DriveClass(event.dest_class)
            except (ValueError, TypeError):
                dest_class = DriveClass.LOCAL
        event.dest_class = dest_class.value

        sensitive = bool(
            event.is_sensitive
            or self.classifier.is_sensitive(event.src_path)
            or self.classifier.is_sensitive(event.dest_path)
        )
        event.is_sensitive = sensitive

        # A single sensitive-file verdict (external => HIGH, local => LOW).
        if sensitive:
            if dest_class.is_external:
                results.append(
                    AuthorizationResult(
                        decision=Decision.SENSITIVE_EXTERNAL,
                        severity=HIGH,
                        reason=(
                            f"sensitive file {event.event_type} to {dest_class.value} "
                            f"destination "
                            f"({self.classifier.explain(event.dest_path or event.src_path)})"
                        ),
                        dest_class=dest_class,
                    )
                )
            else:
                results.append(
                    AuthorizationResult(
                        decision=Decision.SENSITIVE_LOCAL,
                        severity=LOW,
                        reason=(
                            f"sensitive file {event.event_type} on local storage "
                            f"({self.classifier.explain(event.src_path)})"
                        ),
                        dest_class=dest_class,
                    )
                )

        # Bulk detection counts sensitive OR external events per destination,
        # even when an individual non-sensitive transfer is not itself alerted.
        if sensitive or dest_class.is_external:
            key = _destination_root(event.dest_path or event.src_path)
            if dest_class.is_external:
                key = f"{dest_class.value}:{key}"
            else:
                key = f"sensitive:{key}"
            bulk = self._bulk_check(key, time.monotonic())
            if bulk is not None:
                bulk.dest_class = dest_class
                results.append(bulk)

        return results
