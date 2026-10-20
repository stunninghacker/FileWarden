"""SQLite persistence layer: events, alerts and the integrity baseline.

A fresh short-lived connection is opened for every operation (WAL mode) which
keeps the module safe to call from multiple threads - the watchdog observer
thread writes events while the CLI thread may be querying the database.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

# --------------------------------------------------------------------------- #
# Event model
# --------------------------------------------------------------------------- #


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _local_now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class Event:
    """A single observed filesystem event."""

    event_type: str  # created | modified | deleted | moved
    src_path: str
    dest_path: Optional[str] = None
    size: Optional[int] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    pid: Optional[int] = None
    is_sensitive: bool = False
    dest_class: str = "local"
    ts_utc: str = field(default_factory=_utc_now)
    ts_local: str = field(default_factory=_local_now)
    id: Optional[int] = None

    def as_dict(self) -> Dict[str, Any]:
        """Return the event as a plain dictionary (used by the reporter)."""
        return {
            "id": self.id,
            "ts_utc": self.ts_utc,
            "ts_local": self.ts_local,
            "event_type": self.event_type,
            "src_path": self.src_path,
            "dest_path": self.dest_path,
            "size": self.size,
            "user": self.user,
            "process_name": self.process_name,
            "pid": self.pid,
            "is_sensitive": self.is_sensitive,
            "dest_class": self.dest_class,
        }


@dataclass
class Alert:
    """A raised alert."""

    severity: str
    title: str
    detail: str
    src_path: Optional[str] = None
    dest_path: Optional[str] = None
    event_id: Optional[int] = None
    process_name: Optional[str] = None
    ts_utc: str = field(default_factory=_utc_now)
    ts_local: str = field(default_factory=_local_now)
    id: Optional[int] = None

    def as_dict(self) -> Dict[str, Any]:
        """Return the alert as a plain dictionary."""
        return {
            "id": self.id,
            "ts_utc": self.ts_utc,
            "ts_local": self.ts_local,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "src_path": self.src_path,
            "dest_path": self.dest_path,
            "event_id": self.event_id,
            "process_name": self.process_name,
        }


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc        TEXT    NOT NULL,
    ts_local      TEXT    NOT NULL,
    event_type    TEXT    NOT NULL,
    src_path      TEXT    NOT NULL,
    dest_path     TEXT,
    size          INTEGER,
    user          TEXT,
    process_name  TEXT,
    pid           INTEGER,
    is_sensitive  INTEGER DEFAULT 0,
    dest_class    TEXT    DEFAULT 'local'
);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts_utc);
CREATE INDEX IF NOT EXISTS idx_events_sens ON events(is_sensitive);

CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc        TEXT    NOT NULL,
    ts_local      TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    title         TEXT    NOT NULL,
    detail        TEXT,
    src_path      TEXT,
    dest_path     TEXT,
    event_id      INTEGER,
    process_name  TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);

CREATE TABLE IF NOT EXISTS baseline (
    path          TEXT PRIMARY KEY,
    algorithm     TEXT NOT NULL,
    baseline_hash TEXT NOT NULL,
    current_hash  TEXT,
    size          INTEGER,
    mtime         REAL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT
);
"""


class Database:
    """Thin, thread-safe SQLite wrapper."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self._init_schema()

    # ------------------------------------------------------------------ #
    # Connection helpers
    # ------------------------------------------------------------------ #
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=30000;")
        return conn

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        """Serialise access, open a connection, commit and always close it."""
        with self._lock:
            conn = self._connect()
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    def _init_schema(self) -> None:
        with self._session() as conn:
            conn.executescript(SCHEMA)

    # ------------------------------------------------------------------ #
    # Events
    # ------------------------------------------------------------------ #
    def insert_event(self, event: Event) -> int:
        """Persist *event* and return its row id."""
        with self._session() as conn:
            cur = conn.execute(
                """
                INSERT INTO events (ts_utc, ts_local, event_type, src_path, dest_path,
                                    size, user, process_name, pid, is_sensitive, dest_class)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    event.ts_utc,
                    event.ts_local,
                    event.event_type,
                    event.src_path,
                    event.dest_path,
                    event.size,
                    event.user,
                    event.process_name,
                    event.pid,
                    int(bool(event.is_sensitive)),
                    event.dest_class,
                ),
            )
            event.id = int(cur.lastrowid)
            return event.id

    def query_events(
        self,
        limit: Optional[int] = 100,
        event_type: Optional[str] = None,
        sensitive_only: bool = False,
    ) -> List[Event]:
        """Return events, newest first, with optional filters."""
        sql = "SELECT * FROM events"
        clauses: List[str] = []
        params: List[Any] = []
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if sensitive_only:
            clauses.append("is_sensitive = 1")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC"
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        with self._session() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_event(r) for r in rows]

    def count_events_by_type(self) -> Dict[str, int]:
        """Return a ``{event_type: count}`` histogram."""
        with self._session() as conn:
            rows = conn.execute(
                "SELECT event_type, COUNT(*) AS c FROM events GROUP BY event_type"
            ).fetchall()
        return {r["event_type"]: r["c"] for r in rows}

    def total_events(self) -> int:
        """Return the total number of stored events."""
        with self._session() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def sensitive_event_count(self) -> int:
        """Return the number of events flagged sensitive."""
        with self._session() as conn:
            row = conn.execute("SELECT COUNT(*) FROM events WHERE is_sensitive=1").fetchone()
            return int(row[0])

    def top_sensitive_paths(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Return the most frequently touched sensitive paths."""
        with self._session() as conn:
            rows = conn.execute(
                """
                SELECT src_path, COUNT(*) AS c FROM events
                WHERE is_sensitive = 1
                GROUP BY src_path ORDER BY c DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [{"path": r["src_path"], "count": r["c"]} for r in rows]

    def update_event_process(self, path: str, process_name: str, pid: Optional[int]) -> None:
        """Backfill the process owner on the newest event for *path*.

        Used by the asynchronous attributor once a background scan resolves.
        Path comparison is case-insensitive so it works on Windows.
        """
        with self._session() as conn:
            conn.execute(
                """
                UPDATE events SET process_name = ?, pid = ?
                WHERE id = (SELECT id FROM events WHERE lower(src_path) = lower(?)
                            ORDER BY id DESC LIMIT 1)
                """,
                (process_name, pid, path),
            )

    def update_alert_process(self, path: str, process_name: str) -> None:
        """Backfill the process owner on alerts that are still 'unknown'."""
        with self._session() as conn:
            conn.execute(
                """
                UPDATE alerts SET process_name = ?
                WHERE lower(src_path) = lower(?)
                  AND (process_name IS NULL OR process_name = 'unknown')
                """,
                (process_name, path),
            )

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> Event:
        return Event(
            id=row["id"],
            ts_utc=row["ts_utc"],
            ts_local=row["ts_local"],
            event_type=row["event_type"],
            src_path=row["src_path"],
            dest_path=row["dest_path"],
            size=row["size"],
            user=row["user"],
            process_name=row["process_name"],
            pid=row["pid"],
            is_sensitive=bool(row["is_sensitive"]),
            dest_class=row["dest_class"] or "local",
        )

    # ------------------------------------------------------------------ #
    # Alerts
    # ------------------------------------------------------------------ #
    def insert_alert(self, alert: Alert) -> int:
        """Persist *alert* and return its row id."""
        with self._session() as conn:
            cur = conn.execute(
                """
                INSERT INTO alerts (ts_utc, ts_local, severity, title, detail,
                                    src_path, dest_path, event_id, process_name)
                VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (
                    alert.ts_utc,
                    alert.ts_local,
                    alert.severity,
                    alert.title,
                    alert.detail,
                    alert.src_path,
                    alert.dest_path,
                    alert.event_id,
                    alert.process_name,
                ),
            )
            alert.id = int(cur.lastrowid)
            return alert.id

    def query_alerts(
        self, limit: Optional[int] = None, severity: Optional[str] = None
    ) -> List[Alert]:
        """Return alerts, newest first, optionally filtered by severity."""
        sql = "SELECT * FROM alerts"
        params: List[Any] = []
        if severity:
            sql += " WHERE severity = ?"
            params.append(severity)
        sql += " ORDER BY id DESC"
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        with self._session() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_alert(r) for r in rows]

    def count_alerts_by_severity(self) -> Dict[str, int]:
        """Return a ``{severity: count}`` histogram."""
        with self._session() as conn:
            rows = conn.execute(
                "SELECT severity, COUNT(*) AS c FROM alerts GROUP BY severity"
            ).fetchall()
        return {r["severity"]: r["c"] for r in rows}

    def _row_to_alert(self, row: sqlite3.Row) -> Alert:
        return Alert(
            id=row["id"],
            ts_utc=row["ts_utc"],
            ts_local=row["ts_local"],
            severity=row["severity"],
            title=row["title"],
            detail=row["detail"],
            src_path=row["src_path"],
            dest_path=row["dest_path"],
            event_id=row["event_id"],
            process_name=row["process_name"],
        )

    # ------------------------------------------------------------------ #
    # Baseline
    # ------------------------------------------------------------------ #
    def upsert_baseline(
        self,
        path: str,
        algorithm: str,
        digest: str,
        size: Optional[int] = None,
        mtime: Optional[float] = None,
    ) -> None:
        """Insert or update a baseline entry (hash stored as *baseline_hash*)."""
        now = _utc_now()
        with self._session() as conn:
            conn.execute(
                """
                INSERT INTO baseline (path, algorithm, baseline_hash, current_hash,
                                      size, mtime, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT(path) DO UPDATE SET
                    algorithm     = excluded.algorithm,
                    baseline_hash = excluded.baseline_hash,
                    current_hash  = excluded.current_hash,
                    size          = excluded.size,
                    mtime         = excluded.mtime,
                    updated_at    = excluded.updated_at
                """,
                (path, algorithm, digest, digest, size, mtime, now, now),
            )

    def update_current_hash(self, path: str, digest: str) -> None:
        """Record a freshly computed hash for a baselined file."""
        with self._session() as conn:
            conn.execute(
                "UPDATE baseline SET current_hash = ?, updated_at = ? WHERE path = ?",
                (digest, _utc_now(), path),
            )

    def get_baseline(self, path: str) -> Optional[sqlite3.Row]:
        """Return the baseline row for *path*, or ``None``."""
        with self._session() as conn:
            return conn.execute("SELECT * FROM baseline WHERE path = ?", (path,)).fetchone()

    def all_baselines(self) -> List[sqlite3.Row]:
        """Return every baseline row."""
        with self._session() as conn:
            return conn.execute("SELECT * FROM baseline ORDER BY path").fetchall()

    def delete_baseline(self, path: str) -> None:
        """Remove a baseline entry."""
        with self._session() as conn:
            conn.execute("DELETE FROM baseline WHERE path = ?", (path,))

    def baseline_count(self) -> int:
        """Return the number of baselined files."""
        with self._session() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM baseline").fetchone()[0])

    # ------------------------------------------------------------------ #
    # Convenience
    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        """Return a summary dictionary used by ``sftms stats`` and the report."""
        return {
            "total_events": self.total_events(),
            "events_by_type": self.count_events_by_type(),
            "sensitive_events": self.sensitive_event_count(),
            "alerts_by_severity": self.count_alerts_by_severity(),
            "baseline_files": self.baseline_count(),
        }
