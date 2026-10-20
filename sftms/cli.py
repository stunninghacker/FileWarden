"""Command-line interface for SFTMS.

Usage::

    sftms monitor                 start live monitoring (Ctrl-C to stop)
    sftms baseline <dir>          create/update the integrity baseline
    sftms verify                  full integrity scan vs the baseline
    sftms report [--out PATH]     generate the HTML + Markdown audit report
    sftms demo                    run the scripted demo scenario
    sftms stats                   quick database summary
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from .alerts import AlertManager
from .config import Config, ConfigError, load_config
from .db import Database
from .integrity import IntegrityManager
from .monitor import Monitor, run_forever
from .reporter import Reporter

try:
    from rich.console import Console
    from rich.table import Table
except Exception:  # pragma: no cover
    Console = None  # type: ignore[assignment]
    Table = None  # type: ignore[assignment]


def _console():
    """Return a rich Console when available, else ``None``."""
    return Console() if Console else None


def _resolve_config_path(explicit: Optional[str]) -> str:
    """Find the configuration file: explicit -> CWD -> package directory."""
    candidates: List[str] = []
    if explicit:
        candidates.append(explicit)
    candidates.append(os.path.join(os.getcwd(), "config.yaml"))
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(os.path.dirname(here), "config.yaml"))
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    raise ConfigError(
        "Could not find config.yaml; pass --config PATH (tried: "
        + ", ".join(os.path.abspath(c) for c in candidates)
        + ")"
    )


def _load(args) -> Config:
    """Load the resolved config and ensure runtime directories exist."""
    config = load_config(_resolve_config_path(getattr(args, "config", None)))
    config.ensure_runtime_dirs()
    return config


# --------------------------------------------------------------------------- #
# Command implementations
# --------------------------------------------------------------------------- #
def cmd_monitor(args) -> int:
    """Run the live monitor until interrupted."""
    console = _console()
    config = _load(args)
    if console:
        console.print(f"[bold green]SFTMS[/bold green] live monitor - hash={config.hash_algorithm}")
        for directory in config.watch_dirs:
            console.print(f"  watching: [cyan]{directory}[/cyan]"
                          + ("" if os.path.isdir(directory) else " [red](missing)[/red]"))
        console.print(f"  db      : {config.db_path}")
        console.print("  Press [bold]Ctrl-C[/bold] to stop.\n")
    monitor = Monitor(config, console=console)
    run_forever(monitor)
    if console:
        console.print("\n[yellow]Monitor stopped.[/yellow]")
    return 0


def cmd_baseline(args) -> int:
    """Create/update the integrity baseline for a directory."""
    console = _console()
    config = _load(args)
    db = Database(config.db_path)
    alerts = AlertManager(db, config.log_dir, console=console,
                          enable_desktop_notifications=config.enable_desktop_notifications)
    integrity = IntegrityManager(db, algorithm=config.hash_algorithm, alerts=alerts,
                                 protected_dirs=config.sensitive_dirs)
    summary = integrity.create_baseline(args.directory)
    if console:
        console.print(
            f"[green]Baselined {summary['files']} files[/green] under {summary['directory']} "
            f"using {summary['algorithm']}"
        )
    return 0


def cmd_verify(args) -> int:
    """Run a full integrity scan and print the outcome."""
    console = _console()
    config = _load(args)
    db = Database(config.db_path)
    alerts = AlertManager(db, config.log_dir, console=console,
                          enable_desktop_notifications=config.enable_desktop_notifications)
    integrity = IntegrityManager(db, algorithm=config.hash_algorithm, alerts=alerts,
                                 protected_dirs=config.sensitive_dirs)
    result = integrity.verify()

    if console and Table is not None:
        table = Table(title="Integrity verification")
        table.add_column("Status")
        table.add_column("Count", justify="right")
        table.add_row("Intact", str(len(result.intact)))
        table.add_row("Modified", str(len(result.modified)))
        table.add_row("Deleted", str(len(result.deleted)))
        table.add_row("Added (not baselined)", str(len(result.added)))
        console.print(table)
        for path in result.modified:
            console.print(f"  [magenta]MODIFIED[/magenta] {path}")
        for path in result.deleted:
            console.print(f"  [red]DELETED [/red] {path}")
    else:  # pragma: no cover
        print(
            f"intact={len(result.intact)} modified={len(result.modified)} "
            f"deleted={len(result.deleted)} added={len(result.added)}"
        )
    return 1 if (result.modified or result.deleted) else 0


def cmd_report(args) -> int:
    """Generate the HTML + Markdown audit reports."""
    console = _console()
    config = _load(args)
    db = Database(config.db_path)
    integrity = IntegrityManager(db, algorithm=config.hash_algorithm,
                                 protected_dirs=config.sensitive_dirs)
    reporter = Reporter(db, config, integrity=integrity)
    paths = reporter.generate(out_dir=args.out)
    if console:
        console.print(f"[green]HTML report:[/green] {paths['html']}")
        console.print(f"[green]MD report  :[/green] {paths['md']}")
    else:  # pragma: no cover
        print(paths["html"])
        print(paths["md"])
    return 0


def cmd_demo(args) -> int:
    """Run the scripted demonstration scenario."""
    from .demo import run_demo

    summary = run_demo(workdir=args.workdir)
    console = _console()
    if console:
        console.print("\n[bold]Screenshot these:[/bold]")
        console.print("  - colored alerts above (LOW / HIGH / INTEGRITY / CRITICAL)")
        console.print(f"  - alerts log: {summary['alerts_log']}")
        console.print(f"  - report    : {summary['report_html']}")
    return 0


def cmd_stats(args) -> int:
    """Print a quick summary of the database contents."""
    console = _console()
    config = _load(args)
    db = Database(config.db_path)
    stats = db.stats()

    if console and Table is not None:
        table = Table(title="SFTMS statistics")
        table.add_column("Metric")
        table.add_column("Value", justify="right")
        table.add_row("Total events", str(stats["total_events"]))
        table.add_row("Sensitive events", str(stats["sensitive_events"]))
        table.add_row("Baselined files", str(stats["baseline_files"]))
        for event_type, count in sorted(stats["events_by_type"].items()):
            table.add_row(f"  {event_type}", str(count))
        for severity, count in sorted(stats["alerts_by_severity"].items()):
            table.add_row(f"Alert: {severity}", str(count))
        console.print(table)
    else:  # pragma: no cover
        print(stats)
    return 0


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="sftms",
        description="Secure File Transfer Monitoring System (blue-team / DLP toolkit).",
    )
    parser.add_argument(
        "--config", metavar="PATH",
        help="Path to config.yaml (default: ./config.yaml, then the package config).",
    )
    parser.add_argument("--version", action="version", version="sftms 1.0.0")
    sub = parser.add_subparsers(dest="command", required=True)

    p_monitor = sub.add_parser("monitor", help="start live monitoring")
    p_monitor.set_defaults(func=cmd_monitor)

    p_baseline = sub.add_parser("baseline", help="create/update integrity baseline")
    p_baseline.add_argument("directory", help="directory to baseline")
    p_baseline.set_defaults(func=cmd_baseline)

    p_verify = sub.add_parser("verify", help="full integrity scan vs baseline")
    p_verify.set_defaults(func=cmd_verify)

    p_report = sub.add_parser("report", help="generate audit report")
    p_report.add_argument("--out", metavar="PATH", default=None,
                          help="output directory (default: config report_dir)")
    p_report.set_defaults(func=cmd_report)

    p_demo = sub.add_parser("demo", help="run the scripted demo scenario")
    p_demo.add_argument("--workdir", metavar="PATH", default=None,
                        help="directory to create the demo sandbox in")
    p_demo.set_defaults(func=cmd_demo)

    p_stats = sub.add_parser("stats", help="quick database summary")
    p_stats.set_defaults(func=cmd_stats)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point; returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
