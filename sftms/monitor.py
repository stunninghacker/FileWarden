"""Real-time filesystem monitoring built on ``watchdog``.

:class:`Monitor` wires together the classifier, authorizer, integrity checker,
database and alert manager into a single event pipeline:

    watchdog event -> classify path/destination -> persist -> evaluate -> alert

Filesystem events carry no process identifier, so process attribution is
best-effort (see :class:`ProcessAttributor`) and degrades to ``unknown``.
"""

from __future__ import annotations

import getpass
import os
import queue
import sys
import threading
import time
from fnmatch import fnmatch
from typing import Dict, Optional, Tuple

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .alerts import AlertManager
from .authorizer import Authorizer, Decision
from .classifier import Classifier
from .config import Config
from .db import Database, Event
from .hashing import file_size
from .integrity import IntegrityManager

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None  # type: ignore[assignment]


# --------------------------------------------------------------------------- #
# Process attribution
# --------------------------------------------------------------------------- #
class ProcessAttributor:
    """Best-effort, **non-blocking** mapping of a path to the process using it.

    Filesystem notifications carry no PID, so we approximate by scanning
    ``psutil`` for a process with *path* among its open files. That scan is slow
    and must never block the watchdog emitter thread, so it runs on a daemon
    worker thread and :meth:`attribute` returns the cached value immediately
    (``(None, None)`` the first time a path is seen). Results therefore typically
    resolve a moment after the event is logged - which is exactly the
    "best-effort / degrade gracefully" behaviour the tool documents.
    """

    def __init__(
        self,
        enabled: bool = True,
        max_processes: int = 60,
        max_cache: int = 5000,
        scan_budget_seconds: float = 2.0,
        on_result=None,
    ):
        self.enabled = bool(enabled) and psutil is not None
        self.max_processes = max_processes
        self.max_cache = max_cache
        self.scan_budget_seconds = scan_budget_seconds
        self._cache: Dict[str, Tuple[Optional[str], Optional[int]]] = {}
        self._lock = threading.Lock()
        self._queue: "queue.Queue[Optional[str]]" = queue.Queue(maxsize=1000)
        self._on_result = on_result
        self._thread: Optional[threading.Thread] = None
        if self.enabled:
            self._thread = threading.Thread(
                target=self._worker, name="sftms-attributor", daemon=True
            )
            self._thread.start()

    # ------------------------------------------------------------------ #
    def attribute(self, path: str) -> Tuple[Optional[str], Optional[int]]:
        """Return the cached ``(process_name, pid)`` for *path*, else unknown.

        Never blocks: unknown paths are queued for a background scan and the
        call returns immediately.
        """
        if not self.enabled or not path:
            return (None, None)
        key = os.path.normcase(os.path.abspath(path))
        with self._lock:
            cached = self._cache.get(key)
        if cached is not None:
            return cached
        try:
            self._queue.put_nowait(key)
        except queue.Full:  # pragma: no cover - backpressure only
            pass
        return (None, None)

    # ------------------------------------------------------------------ #
    def _scan(self, target: str) -> Tuple[Optional[str], Optional[int]]:
        """Scan open files (run on the worker thread); never raises."""
        found: Tuple[Optional[str], Optional[int]] = (None, None)
        scanned = 0
        deadline = time.monotonic() + self.scan_budget_seconds
        try:
            for proc in psutil.process_iter(["pid", "name"]):  # type: ignore[union-attr]
                if scanned >= self.max_processes or time.monotonic() > deadline:
                    break
                scanned += 1
                try:
                    for open_file in proc.open_files():
                        if os.path.normcase(open_file.path) == target:
                            found = (proc.info.get("name"), proc.info.get("pid"))
                            break
                    if found[0]:
                        break
                except Exception:
                    continue
                time.sleep(0)  # cooperate with the emitter thread
        except Exception:
            found = (None, None)
        return found

    def _worker(self) -> None:  # pragma: no cover - background thread
        while True:
            key = self._queue.get()
            if key is None:
                return
            result = self._scan(key)
            with self._lock:
                if len(self._cache) >= self.max_cache:
                    self._cache.clear()
                self._cache[key] = result
            if self._on_result is not None:
                try:
                    self._on_result(key, result)
                except Exception:
                    pass

    def stop(self) -> None:
        """Signal the worker thread to exit."""
        if self._thread is not None:
            try:
                self._queue.put_nowait(None)
            except queue.Full:  # pragma: no cover
                pass


def current_user() -> str:
    """Return the current username, degrading gracefully."""
    try:
        return getpass.getuser()
    except Exception:
        pass
    if psutil is not None:
        try:
            return psutil.Process().username()
        except Exception:
            pass
    return "unknown"


# --------------------------------------------------------------------------- #
# watchdog handler
# --------------------------------------------------------------------------- #
class _SFTMSEventHandler(FileSystemEventHandler):
    """Translates watchdog callbacks into :class:`Monitor` calls."""

    def __init__(self, monitor: "Monitor"):
        self.monitor = monitor

    def _safe(self, kind: str, src_path: str, dest_path: Optional[str] = None) -> None:
        """Guard the pipeline so one bad event can never kill the observer."""
        try:
            self.monitor.handle_event(kind, src_path, dest_path)
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[sftms] error handling {kind} {src_path}: {exc}", file=sys.stderr)

    def on_created(self, event):  # noqa: D401 - watchdog signature
        if not event.is_directory:
            self._safe("created", event.src_path)

    def on_modified(self, event):  # noqa: D401
        if not event.is_directory:
            self._safe("modified", event.src_path)

    def on_deleted(self, event):  # noqa: D401
        if not event.is_directory:
            self._safe("deleted", event.src_path)

    def on_moved(self, event):  # noqa: D401
        if not event.is_directory:
            self._safe("moved", event.src_path, event.dest_path)


# --------------------------------------------------------------------------- #
# Monitor
# --------------------------------------------------------------------------- #
class Monitor:
    """Owns the watchdog observers and the event-processing pipeline."""

    def __init__(
        self,
        config: Config,
        db: Optional[Database] = None,
        alerts: Optional[AlertManager] = None,
        classifier: Optional[Classifier] = None,
        authorizer: Optional[Authorizer] = None,
        integrity: Optional[IntegrityManager] = None,
        console=None,
    ):
        self.config = config
        self.db = db or Database(config.db_path)
        self.classifier = classifier or Classifier(
            config.sensitive_dirs, config.sensitive_patterns
        )
        self.authorizer = authorizer or Authorizer(
            self.classifier,
            cloud_patterns=config.cloud_folder_patterns,
            removable_patterns=config.removable_path_patterns,
            network_patterns=config.network_path_patterns,
            bulk_threshold=config.bulk_threshold,
            bulk_window_seconds=config.bulk_window_seconds,
        )
        self.alerts = alerts or AlertManager(
            self.db,
            config.log_dir,
            console=console,
            enable_desktop_notifications=config.enable_desktop_notifications,
        )
        self.integrity = integrity or IntegrityManager(
            self.db,
            algorithm=config.hash_algorithm,
            alerts=self.alerts,
            protected_dirs=config.sensitive_dirs,
        )
        self.attributor = ProcessAttributor(
            enabled=config.enable_process_attribution,
            on_result=self._on_attribution,
        )
        self._observer: Optional[Observer] = None
        self._running = False
        self._user = current_user()
        self._stats = {"events": 0, "alerts": 0}
        # Collapse duplicate callbacks (create+modify) for the same decision.
        self._raise_cooldown = 2.0
        self._recent_raise: Dict[Tuple[str, str], float] = {}

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        """Start watching every configured directory (non-blocking)."""
        if self._running:
            return
        handler = _SFTMSEventHandler(self)
        self._observer = Observer()
        for directory in self.config.watch_dirs:
            if os.path.isdir(directory):
                self._observer.schedule(handler, directory, recursive=True)
            # Non-existent watch dirs are skipped rather than fatal.
        self._observer.start()
        self._running = True

    def stop(self) -> None:
        """Stop the observers and the attributor, then wait for threads to exit."""
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
        self.attributor.stop()
        self._running = False

    def _on_attribution(self, path_key: str, result: Tuple[Optional[str], Optional[int]]) -> None:
        """Backfill process info on stored events/alerts (async worker thread)."""
        name, pid = result
        if not name:
            return
        try:
            self.db.update_event_process(path_key, name, pid)
            self.db.update_alert_process(path_key, name)
        except Exception:  # pragma: no cover - best effort only
            pass

    def __enter__(self) -> "Monitor":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    @property
    def running(self) -> bool:
        """True while the observer thread is active."""
        return self._running

    @property
    def stats(self) -> Dict[str, int]:
        """Return a small counter dict (``events`` / ``alerts``)."""
        return dict(self._stats)

    # ------------------------------------------------------------------ #
    # Ignoring
    # ------------------------------------------------------------------ #
    def _ignored(self, path: Optional[str]) -> bool:
        """Return True if *path* matches an ``ignore_patterns`` glob."""
        if not path:
            return False
        norm = os.path.normpath(os.path.abspath(path)).replace("\\", "/")
        low = norm.lower()
        base = os.path.basename(low)
        for pattern in self.config.ignore_patterns:
            pat = pattern.replace("\\", "/").lower()
            if fnmatch(low, pat) or fnmatch(base, pat):
                return True
        return False

    # ------------------------------------------------------------------ #
    # Event pipeline
    # ------------------------------------------------------------------ #
    def handle_event(
        self, event_type: str, src_path: str, dest_path: Optional[str] = None
    ) -> Optional[Event]:
        """Process one filesystem event end-to-end; returns the stored event.

        Returns ``None`` when the event is ignored.
        """
        if self._ignored(src_path) or self._ignored(dest_path):
            return None

        reference = dest_path or src_path
        size = file_size(reference)
        process_name, pid = self.attributor.attribute(reference)

        event = Event(
            event_type=event_type,
            src_path=src_path,
            dest_path=dest_path,
            size=size,
            user=self._user,
            process_name=process_name or "unknown",
            pid=pid,
        )

        # Classify before persisting so the stored row carries the verdict.
        src_sensitive = self.classifier.is_sensitive(src_path)
        dest_sensitive = self.classifier.is_sensitive(dest_path)
        event.is_sensitive = src_sensitive or dest_sensitive
        event.dest_class = self.authorizer.classify_dest(reference).value

        try:
            self.db.insert_event(event)
        except Exception:  # pragma: no cover - persistence must not stop monitoring
            pass
        self._stats["events"] += 1

        # Evaluate -> raise alerts.
        try:
            results = self.authorizer.evaluate(event)
        except Exception:
            results = []
        for result in results:
            self._raise(result, event)

        # Integrity: recompute hash on modification of baselined files.
        if event_type == "modified":
            try:
                self.integrity.check_modification(src_path)
            except Exception:  # pragma: no cover
                pass

        return event

    def _raise(self, result, event: Event) -> None:
        """Translate an :class:`AuthorizationResult` into an alert."""
        titles = {
            Decision.SENSITIVE_EXTERNAL: "Sensitive file transferred to external location",
            Decision.SENSITIVE_LOCAL: "Sensitive file accessed",
            Decision.BULK_EXFILTRATION: "Possible bulk exfiltration (CRITICAL)",
        }
        title = titles.get(result.decision, "Suspicious file activity")

        # De-duplicate bursty callbacks (watchdog emits create+modify for a copy).
        key = (result.decision.value, os.path.normcase(event.dest_path or event.src_path))
        now = time.monotonic()
        if now - self._recent_raise.get(key, 0.0) < self._raise_cooldown:
            return
        self._recent_raise[key] = now

        self.alerts.emit(
            severity=result.severity,
            title=title,
            detail=result.reason,
            src_path=event.src_path,
            dest_path=event.dest_path,
            event=event,
        )
        self._stats["alerts"] += 1


def run_forever(monitor: Monitor) -> None:
    """Block, keeping *monitor* alive until KeyboardInterrupt (Ctrl-C)."""
    monitor.start()
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()


__all__ = ["Monitor", "ProcessAttributor", "current_user", "run_forever"]
