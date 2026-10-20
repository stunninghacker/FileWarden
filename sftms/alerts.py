"""Alert handling: severity model, console output, log file, DB and toasts.

Severities
----------
``LOW``
    A sensitive file was touched on local storage.
``HIGH``
    A sensitive file was copied/moved to a removable, network or cloud target.
``CRITICAL``
    Possible bulk exfiltration (burst of sensitive/external events).
``INTEGRITY``
    A baselined file's hash no longer matches (tamper / corruption).
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from typing import Optional

try:
    from rich.console import Console
    from rich.text import Text
except Exception:  # pragma: no cover - rich is a declared dependency
    Console = None  # type: ignore[assignment]
    Text = None  # type: ignore[assignment]

from .db import Alert, Database

# --------------------------------------------------------------------------- #
# Severity constants
# --------------------------------------------------------------------------- #

LOW = "LOW"
HIGH = "HIGH"
CRITICAL = "CRITICAL"
INTEGRITY = "INTEGRITY"

#: Higher number == more severe (used for sorting / summarising).
SEVERITY_ORDER = {LOW: 1, HIGH: 2, INTEGRITY: 3, CRITICAL: 4}

#: Rich style per severity.
_SEVERITY_STYLE = {
    LOW: "bold cyan",
    HIGH: "bold yellow",
    CRITICAL: "bold white on red",
    INTEGRITY: "bold magenta",
}

_SEVERITY_EMOJI = {LOW: "[.]", HIGH: "[!]", CRITICAL: "[X]", INTEGRITY: "[#]"}


class AlertManager:
    """Raises alerts to every configured sink.

    Sinks: colored console (rich), ``alerts.log``, the SQLite database and,
    when available, an OS desktop notification via ``plyer`` (import-guarded).
    Optional desktop notifications are also toggleable from the config.
    """

    def __init__(
        self,
        db: Database,
        log_dir: str,
        console: Optional["Console"] = None,
        enable_desktop_notifications: bool = False,
    ):
        self.db = db
        self.log_dir = log_dir
        self.console = console if console is not None else (Console() if Console else None)
        self.enable_desktop_notifications = enable_desktop_notifications
        self._lock = threading.Lock()
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_path = os.path.join(self.log_dir, "alerts.log")

    # ------------------------------------------------------------------ #
    def emit(
        self,
        severity: str,
        title: str,
        detail: str,
        src_path: Optional[str] = None,
        dest_path: Optional[str] = None,
        event: Optional[object] = None,
        process_name: Optional[str] = None,
        event_id: Optional[int] = None,
    ) -> Alert:
        """Create, persist and broadcast a single alert; returns the alert."""
        alert = Alert(
            severity=severity,
            title=title,
            detail=detail,
            src_path=src_path,
            dest_path=dest_path,
            event_id=event_id if event_id is not None else getattr(event, "id", None),
            process_name=(
                process_name if process_name is not None else getattr(event, "process_name", None)
            ),
        )
        self._to_db(alert)
        self._to_console(alert)
        self._to_file(alert)
        if self.enable_desktop_notifications:
            self._to_desktop(alert)
        return alert

    # ------------------------------------------------------------------ #
    def _to_db(self, alert: Alert) -> None:
        try:
            self.db.insert_alert(alert)
        except Exception:  # pragma: no cover - never let logging break the monitor
            pass

    def _to_file(self, alert: Alert) -> None:
        line = (
            f"{alert.ts_utc}\t{alert.severity}\t{alert.title}\t"
            f"src={alert.src_path}\tdest={alert.dest_path}\tproc={alert.process_name}\t"
            f"detail={alert.detail}\n"
        )
        with self._lock:
            try:
                with open(self.log_path, "a", encoding="utf-8") as fh:
                    fh.write(line)
            except OSError:  # pragma: no cover - defensive
                pass

    def _to_console(self, alert: Alert) -> None:
        if self.console is None:
            return
        style = _SEVERITY_STYLE.get(alert.severity, "bold white")
        marker = _SEVERITY_EMOJI.get(alert.severity, "[?]")
        line = Text()
        line.append(f"{marker} {alert.severity:<9} ", style=style)
        line.append(f"{alert.title}", style=style)
        self.console.print(line)
        if alert.src_path:
            self.console.print(f"    src : [dim]{alert.src_path}[/dim]")
        if alert.dest_path:
            self.console.print(f"    dest: [dim]{alert.dest_path}[/dim]")
        if alert.process_name:
            self.console.print(f"    proc: [dim]{alert.process_name}[/dim]")
        self.console.print(f"    info: [italic]{alert.detail}[/italic]")

    def _to_desktop(self, alert: Alert) -> None:
        try:  # pragma: no cover - depends on optional dependency + OS
            from plyer import notification  # type: ignore

            notification.notify(
                title=f"SFTMS {alert.severity}: {alert.title}",
                message=alert.detail[:250],
                app_name="SFTMS",
                timeout=10,
            )
        except Exception:
            # plyer missing or no notification backend - silently ignore.
            pass


def utc_now() -> str:
    """Return the current UTC time in the canonical alert format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
