"""Scripted, self-contained demo that fires every alert type.

``sftms demo`` (and ``scripts/demo.py``) call :func:`run_demo`, which:

1. builds a temporary sandbox with a fake *sensitive* folder and fake files,
2. writes a demo config and takes an integrity baseline,
3. starts the monitor in a background thread,
4. drives the scenarios:
   * HIGH   - copy a sensitive file to a simulated cloud folder (Dropbox),
   * HIGH   - copy a sensitive file to a simulated removable drive (USB),
   * HIGH   - copy a sensitive file to a simulated network share (SMB),
   * LOW    - touch a sensitive file on local storage,
   * INTEGRITY - modify a baselined file so its hash no longer matches,
   * CRITICAL - rapidly move 60 files to the "USB" drive (bulk exfiltration),
5. stops the monitor, verifies integrity and auto-generates the report.

Everything happens under one temporary directory, which is printed at the end
so it can be inspected / screenshotted.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
from typing import Any, Dict, Optional

import yaml

from .config import Config
from .db import Database
from .integrity import IntegrityManager
from .monitor import Monitor
from .alerts import AlertManager
from .reporter import Reporter

try:
    from rich.console import Console
    from rich.rule import Rule
except Exception:  # pragma: no cover
    Console = None  # type: ignore[assignment]
    Rule = None  # type: ignore[assignment]

BULK_FILES = 60


def _say(console, message: str = "") -> None:
    """Print a message, using rich when available."""
    if console is not None:
        console.print(message)
    else:  # pragma: no cover
        print(message)


def _section(console, title: str) -> None:
    """Print a section rule."""
    if console is not None and Rule is not None:
        console.print(Rule(f"[bold]{title}[/bold]"))
    else:  # pragma: no cover
        print(f"\n=== {title} ===")


def _write(path: str, content: str) -> None:
    """Write UTF-8 text, creating parent directories as needed."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def _wait_for_usb_events(db: Database, usb_dir: str, expected: int, timeout: float = 20.0) -> int:
    """Block until *expected* events target *usb_dir*, or *timeout* elapses.

    Used to drain the observer after the burst so the bulk alert is not lost to
    a stop/observe race. Returns the number of matching events observed.
    """
    needle = os.path.normcase(usb_dir)
    deadline = time.monotonic() + timeout
    seen = 0
    while time.monotonic() < deadline:
        seen = sum(
            1
            for event in db.query_events(limit=1000)
            if needle in os.path.normcase(event.dest_path or event.src_path)
        )
        if seen >= expected:
            break
        time.sleep(0.25)
    return seen


def _build_config_dict(sandbox: str, run_dir: str) -> Dict[str, Any]:
    """Return the demo configuration as a plain dict."""
    return {
        "watch_dirs": [sandbox],
        "sensitive_dirs": [os.path.join(sandbox, "sensitive")],
        "sensitive_patterns": [
            "*.key", "*.pem", "*.env", "*secret*", "*credential*",
            "payroll*", "*ssn*", "*.xlsx", "*confidential*",
        ],
        "cloud_folder_patterns": [
            "*dropbox*", "*onedrive*", "*google drive*", "*gdrive*", "*icloud*",
        ],
        "removable_path_patterns": ["*usb*", "*removable*", "*/media/*"],
        "network_path_patterns": ["*smb*", "*nfs*", "*\\\\*\\*"],
        "ignore_patterns": ["*.tmp", "*~", "*.swp"],
        "hash_algorithm": "sha256",
        "bulk_threshold": 50,
        "bulk_window_seconds": 60,
        "db_path": os.path.join(run_dir, "events.db"),
        "log_dir": os.path.join(run_dir, "logs"),
        "report_dir": os.path.join(run_dir, "reports"),
        "enable_desktop_notifications": False,
        # Off for a fast, deterministic demo (see config.yaml for the trade-off).
        "enable_process_attribution": False,
    }


def run_demo(workdir: Optional[str] = None, keep: bool = True) -> Dict[str, Any]:
    """Run the full demo and return a summary dictionary.

    Parameters
    ----------
    workdir:
        Optional directory to create the sandbox in. When omitted a fresh
        temporary directory is used.
    keep:
        When True (default) the sandbox is *not* deleted, so artefacts can be
        inspected and screenshotted.
    """
    console = Console() if Console else None
    root = workdir or tempfile.mkdtemp(prefix="sftms_demo_")
    os.makedirs(root, exist_ok=True)

    sandbox = os.path.join(root, "sandbox")
    sensitive = os.path.join(sandbox, "sensitive")
    normal = os.path.join(sandbox, "normal")
    dropbox = os.path.join(sandbox, "Dropbox")
    usb = os.path.join(sandbox, "usb_drive")
    smb = os.path.join(sandbox, "smb_share")
    run_dir = os.path.join(root, "run")

    for directory in (sensitive, normal, dropbox, usb, smb, run_dir):
        os.makedirs(directory, exist_ok=True)

    # ------------------------------------------------------------------ #
    _section(console, "1. Building sandbox and demo configuration")
    _write(os.path.join(sensitive, "payroll_2024.xlsx"), "fake payroll data\n")
    _write(os.path.join(sensitive, "id_rsa.key"), "-----BEGIN PRIVATE KEY-----\nFAKE\n")
    _write(os.path.join(sensitive, "secrets.env"), "API_KEY=fake-secret-value\n")
    _write(os.path.join(sensitive, "api_credentials.pem"), "-----BEGIN CERTIFICATE-----\nFAKE\n")
    _write(os.path.join(sensitive, "customer_ssn.csv"), "name,ssn\nJohn Doe,000-00-0000\n")
    _write(os.path.join(normal, "notes.txt"), "a harmless note\n")
    _write(os.path.join(normal, "agenda.docx"), "not really a docx\n")

    config_dict = _build_config_dict(sandbox, run_dir)
    config_path = os.path.join(root, "config.yaml")
    with open(config_path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(config_dict, handle, sort_keys=False)
    config = Config.from_dict(config_dict, base_dir=root)
    config.ensure_runtime_dirs()

    _say(console, f"[green]Sandbox:[/green] {sandbox}")
    _say(console, f"[green]Config :[/green] {config_path}")

    # ------------------------------------------------------------------ #
    _section(console, "2. Creating integrity baseline of sensitive files")
    db = Database(config.db_path)
    alerts = AlertManager(
        db,
        config.log_dir,
        console=console,
        enable_desktop_notifications=config.enable_desktop_notifications,
    )
    integrity = IntegrityManager(
        db, algorithm=config.hash_algorithm, alerts=alerts, protected_dirs=config.sensitive_dirs
    )
    baseline = integrity.create_baseline(sensitive)
    _say(console, f"[cyan]Baselined {baseline['files']} files ({config.hash_algorithm}).[/cyan]")

    # ------------------------------------------------------------------ #
    _section(console, "3. Starting the live monitor")
    monitor = Monitor(config, db=db, alerts=alerts, integrity=integrity, console=console)
    monitor.start()
    time.sleep(1.0)

    def wait(seconds: float = 1.2) -> None:
        time.sleep(seconds)

    try:
        # --- HIGH: sensitive file -> cloud ------------------------------- #
        _section(console, "4. Scenario A: copy payroll file to cloud (Dropbox) -> HIGH")
        shutil.copy2(
            os.path.join(sensitive, "payroll_2024.xlsx"),
            os.path.join(dropbox, "payroll_2024.xlsx"),
        )
        wait()

        # --- HIGH: sensitive file -> removable -------------------------- #
        _section(console, "5. Scenario B: copy private key to USB drive -> HIGH")
        shutil.copy2(os.path.join(sensitive, "id_rsa.key"), os.path.join(usb, "id_rsa.key"))
        wait()

        # --- HIGH: sensitive file -> network ---------------------------- #
        _section(console, "6. Scenario C: copy credential file to SMB share -> HIGH")
        shutil.copy2(
            os.path.join(sensitive, "api_credentials.pem"),
            os.path.join(smb, "api_credentials.pem"),
        )
        wait()

        # --- LOW: sensitive file touched locally ------------------------ #
        _section(console, "7. Scenario D: create + modify sensitive file locally -> LOW")
        new_file = os.path.join(sensitive, "confidential_offer.pdf")
        _write(new_file, "draft offer\n")
        wait(0.8)
        with open(new_file, "a", encoding="utf-8") as handle:
            handle.write("revised terms\n")
        wait()

        # --- INTEGRITY: tamper with a baselined file -------------------- #
        _section(console, "8. Scenario E: tamper with baselined file -> INTEGRITY")
        with open(os.path.join(sensitive, "secrets.env"), "a", encoding="utf-8") as handle:
            handle.write("UNAUTHORIZED_EDIT=1\n")
        wait(1.5)

        # --- CRITICAL: bulk exfiltration -------------------------------- #
        _section(console, f"9. Scenario F: move {BULK_FILES} files to USB -> CRITICAL")
        bulk_sources = []
        for i in range(BULK_FILES):
            path = os.path.join(normal, f"bulk_{i:02d}.txt")
            _write(path, f"bulk file {i}\n")
            bulk_sources.append(path)
        wait(1.0)
        for path in bulk_sources:
            shutil.move(path, os.path.join(usb, os.path.basename(path)))
        # Drain: wait until the observer has recorded a destination event for
        # every bulk move (or a generous timeout), so the CRITICAL verdict is
        # not lost to a stop/observe race on slow machines.
        _wait_for_usb_events(db, usb, BULK_FILES, timeout=20.0)
        wait(1.0)
    finally:
        monitor.stop()
        time.sleep(0.5)

    # ------------------------------------------------------------------ #
    _section(console, "10. Verifying integrity (baseline vs current)")
    result = integrity.verify(emit_alerts=False)
    _say(
        console,
        f"[cyan]intact={len(result.intact)} modified={len(result.modified)} "
        f"deleted={len(result.deleted)} added={len(result.added)}[/cyan]",
    )

    # ------------------------------------------------------------------ #
    _section(console, "11. Generating audit report")
    reporter = Reporter(db, config, integrity=integrity)
    paths = reporter.generate()

    # ------------------------------------------------------------------ #
    summary = {
        "root": root,
        "sandbox": sandbox,
        "db_path": config.db_path,
        "alerts_log": alerts.log_path,
        "report_html": paths["html"],
        "report_md": paths["md"],
        "stats": db.stats(),
        "monitor_stats": monitor.stats,
        "integrity": {
            "intact": len(result.intact),
            "modified": len(result.modified),
            "deleted": len(result.deleted),
            "added": len(result.added),
        },
    }

    _section(console, "Demo complete")
    _say(console, f"[bold green]Report (HTML):[/bold green] {paths['html']}")
    _say(console, f"[bold green]Report (MD)  :[/bold green] {paths['md']}")
    _say(console, f"[bold green]Alerts log   :[/bold green] {alerts.log_path}")
    severities = summary["stats"]["alerts_by_severity"]
    _say(
        console,
        "[bold]Alerts raised:[/bold] "
        + ", ".join(f"{k}={v}" for k, v in sorted(severities.items())) or "none",
    )
    return summary


def main() -> None:  # pragma: no cover - thin CLI wrapper
    """Standalone entry point (``python -m sftms.demo``)."""
    run_demo()


if __name__ == "__main__":  # pragma: no cover
    main()
