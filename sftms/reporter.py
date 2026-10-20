"""Audit report generation (HTML via Jinja2 + Markdown).

Summarises: total events by type, alerts grouped by severity, integrity
results, the most frequently touched sensitive files and a chronological
timeline. Produces a timestamped ``.html`` and ``.md`` file in the report dir.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from jinja2 import Environment, select_autoescape

from .config import Config
from .db import Database
from .integrity import IntegrityManager

# --------------------------------------------------------------------------- #
# HTML template (kept inline so the tool stays a single self-contained package)
# --------------------------------------------------------------------------- #
_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SFTMS Audit Report - {{ generated_local }}</title>
<style>
  :root { --bg:#0f1419; --panel:#1b222b; --ink:#e6edf3; --muted:#9aa7b4;
          --crit:#ff4d4f; --high:#ffb020; --low:#38bdf8; --intg:#c084fc; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--ink);
         font-family: "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  header { padding:24px 32px; background:linear-gradient(90deg,#101820,#1b2735); border-bottom:1px solid #2b3746; }
  h1 { margin:0 0 4px; font-size:22px; }
  h2 { margin:32px 32px 8px; font-size:18px; border-left:4px solid #38bdf8; padding-left:10px; }
  .sub { color:var(--muted); font-size:13px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px; padding:20px 32px; }
  .card { background:var(--panel); border:1px solid #2b3746; border-radius:10px; padding:16px; }
  .card .n { font-size:28px; font-weight:700; }
  .card .l { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }
  table { width:calc(100% - 64px); margin:8px 32px 24px; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:8px 10px; border-bottom:1px solid #243040; vertical-align:top; }
  th { color:var(--muted); text-transform:uppercase; font-size:11px; letter-spacing:.06em; }
  code { background:#0b0f14; padding:2px 6px; border-radius:5px; font-size:12px; word-break:break-all; }
  .sev { padding:2px 8px; border-radius:20px; font-size:11px; font-weight:700; }
  .LOW { background:rgba(56,189,248,.18); color:var(--low); }
  .HIGH { background:rgba(255,176,32,.18); color:var(--high); }
  .CRITICAL { background:rgba(255,77,79,.20); color:var(--crit); }
  .INTEGRITY { background:rgba(192,132,252,.18); color:var(--intg); }
  .empty { color:var(--muted); margin:0 32px 24px; font-style:italic; }
  footer { color:var(--muted); font-size:12px; padding:24px 32px; border-top:1px solid #243040; }
</style>
</head>
<body>
<header>
  <h1>Secure File Transfer Monitoring System - Audit Report</h1>
  <div class="sub">Generated {{ generated_local }} ({{ generated_utc }}) &middot; hash={{ hash_algorithm }}</div>
</header>

<div class="grid">
  <div class="card"><div class="n">{{ stats.total_events }}</div><div class="l">Total events</div></div>
  <div class="card"><div class="n" style="color:var(--intg)">{{ stats.sensitive_events }}</div><div class="l">Sensitive events</div></div>
  <div class="card"><div class="n" style="color:var(--high)">{{ alert_total }}</div><div class="l">Total alerts</div></div>
  <div class="card"><div class="n" style="color:var(--crit)">{{ stats.alerts_by_severity.get('CRITICAL', 0) }}</div><div class="l">Critical</div></div>
  <div class="card"><div class="n">{{ stats.baseline_files }}</div><div class="l">Baselined files</div></div>
  <div class="card"><div class="n">{{ integrity.modified|length }}</div><div class="l">Integrity failures</div></div>
</div>

<h2>Events by type</h2>
<table>
  <tr><th>Event type</th><th>Count</th></tr>
  {% for k, v in stats.events_by_type.items() %}
  <tr><td>{{ k }}</td><td>{{ v }}</td></tr>
  {% else %}
  <tr><td colspan="2" class="empty">No events recorded.</td></tr>
  {% endfor %}
</table>

<h2>Alerts by severity</h2>
<table>
  <tr><th>Severity</th><th>Count</th></tr>
  {% for sev in ['CRITICAL','INTEGRITY','HIGH','LOW'] %}
  <tr><td><span class="sev {{ sev }}">{{ sev }}</span></td><td>{{ stats.alerts_by_severity.get(sev, 0) }}</td></tr>
  {% endfor %}
</table>

<h2>Violations / alerts</h2>
{% if alerts %}
<table>
  <tr><th>Time (UTC)</th><th>Severity</th><th>Title</th><th>Source</th><th>Destination</th><th>Detail</th></tr>
  {% for a in alerts %}
  <tr>
    <td>{{ a.ts_utc }}</td>
    <td><span class="sev {{ a.severity }}">{{ a.severity }}</span></td>
    <td>{{ a.title }}</td>
    <td><code>{{ a.src_path or '-' }}</code></td>
    <td><code>{{ a.dest_path or '-' }}</code></td>
    <td>{{ a.detail }}</td>
  </tr>
  {% endfor %}
</table>
{% else %}
<p class="empty">No alerts raised.</p>
{% endif %}

<h2>Integrity results</h2>
<table>
  <tr><th>Status</th><th>Count</th></tr>
  <tr><td>Intact</td><td>{{ integrity.intact|length }}</td></tr>
  <tr><td>Modified (hash mismatch)</td><td>{{ integrity.modified|length }}</td></tr>
  <tr><td>Deleted</td><td>{{ integrity.deleted|length }}</td></tr>
  <tr><td>Added (not baselined)</td><td>{{ integrity.added|length }}</td></tr>
</table>
{% if integrity.modified or integrity.deleted %}
<table>
  <tr><th>File</th><th>Status</th></tr>
  {% for p in integrity.modified %}<tr><td><code>{{ p }}</code></td><td>MODIFIED</td></tr>{% endfor %}
  {% for p in integrity.deleted %}<tr><td><code>{{ p }}</code></td><td>DELETED</td></tr>{% endfor %}
</table>
{% endif %}

<h2>Top sensitive files touched</h2>
{% if top_paths %}
<table>
  <tr><th>Path</th><th>Times touched</th></tr>
  {% for p in top_paths %}<tr><td><code>{{ p.path }}</code></td><td>{{ p.count }}</td></tr>{% endfor %}
</table>
{% else %}
<p class="empty">No sensitive files touched.</p>
{% endif %}

<h2>Timeline (most recent {{ timeline|length }} events)</h2>
{% if timeline %}
<table>
  <tr><th>Time (UTC)</th><th>Type</th><th>Source</th><th>Destination</th><th>Dest class</th><th>Sensitive</th></tr>
  {% for e in timeline %}
  <tr>
    <td>{{ e.ts_utc }}</td>
    <td>{{ e.event_type }}</td>
    <td><code>{{ e.src_path }}</code></td>
    <td><code>{{ e.dest_path or '-' }}</code></td>
    <td>{{ e.dest_class }}</td>
    <td>{{ 'YES' if e.is_sensitive else '' }}</td>
  </tr>
  {% endfor %}
</table>
{% else %}
<p class="empty">No events.</p>
{% endif %}

<footer>SFTMS 1.0.0 &middot; generated automatically - handle as confidential.</footer>
</body>
</html>
"""


class Reporter:
    """Builds and writes the HTML + Markdown audit reports."""

    def __init__(self, db: Database, config: Config, integrity: Optional[IntegrityManager] = None):
        self.db = db
        self.config = config
        self.integrity = integrity
        self.env = Environment(autoescape=select_autoescape(["html", "xml"]))
        self.template = self.env.from_string(_HTML_TEMPLATE)

    # ------------------------------------------------------------------ #
    def collect(self, timeline_limit: int = 300) -> Dict[str, Any]:
        """Gather everything the report needs into a context dictionary."""
        stats = self.db.stats()
        alerts = [a.as_dict() for a in self.db.query_alerts()]
        timeline = [e.as_dict() for e in self.db.query_events(limit=timeline_limit)]
        timeline.reverse()  # chronological

        integrity_data = {"intact": [], "modified": [], "deleted": [], "added": []}
        if self.integrity is not None:
            result = self.integrity.verify(emit_alerts=False)
            integrity_data = {
                "intact": result.intact,
                "modified": result.modified,
                "deleted": result.deleted,
                "added": result.added,
            }

        now = datetime.now(timezone.utc)
        return {
            "stats": stats,
            "alerts": alerts,
            "alert_total": sum(stats.get("alerts_by_severity", {}).values()),
            "integrity": integrity_data,
            "top_paths": self.db.top_sensitive_paths(10),
            "timeline": timeline,
            "hash_algorithm": self.config.hash_algorithm,
            "generated_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "generated_local": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    def render_html(self, context: Dict[str, Any]) -> str:
        """Render the HTML report from a context dict."""
        return self.template.render(**context)

    def render_markdown(self, context: Dict[str, Any]) -> str:
        """Render the Markdown report from a context dict."""
        stats = context["stats"]
        lines: List[str] = []
        lines.append("# Secure File Transfer Monitoring System - Audit Report")
        lines.append("")
        lines.append(f"- Generated (UTC): {context['generated_utc']}")
        lines.append(f"- Generated (local): {context['generated_local']}")
        lines.append(f"- Hash algorithm: `{context['hash_algorithm']}`")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- Total events: **{stats['total_events']}**")
        lines.append(f"- Sensitive events: **{stats['sensitive_events']}**")
        lines.append(f"- Total alerts: **{context['alert_total']}**")
        lines.append(f"- Baselined files: **{stats['baseline_files']}**")
        lines.append(f"- Integrity failures: **{len(context['integrity']['modified'])}**")
        lines.append("")

        lines.append("## Events by type")
        lines.append("")
        lines.append("| Event type | Count |")
        lines.append("|------------|-------|")
        for k, v in stats["events_by_type"].items():
            lines.append(f"| {k} | {v} |")
        if not stats["events_by_type"]:
            lines.append("| _(none)_ | 0 |")
        lines.append("")

        lines.append("## Alerts by severity")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ("CRITICAL", "INTEGRITY", "HIGH", "LOW"):
            lines.append(f"| {sev} | {stats['alerts_by_severity'].get(sev, 0)} |")
        lines.append("")

        lines.append("## Violations / alerts")
        lines.append("")
        if context["alerts"]:
            lines.append("| Time (UTC) | Severity | Title | Source | Destination | Detail |")
            lines.append("|------------|----------|-------|--------|-------------|--------|")
            for a in context["alerts"]:
                lines.append(
                    f"| {a['ts_utc']} | {a['severity']} | {a['title']} | "
                    f"`{a['src_path'] or '-'}` | `{a['dest_path'] or '-'}` | {a['detail']} |"
                )
        else:
            lines.append("_No alerts raised._")
        lines.append("")

        lines.append("## Integrity results")
        lines.append("")
        integ = context["integrity"]
        lines.append(f"- Intact: {len(integ['intact'])}")
        lines.append(f"- Modified: {len(integ['modified'])}")
        lines.append(f"- Deleted: {len(integ['deleted'])}")
        lines.append(f"- Added: {len(integ['added'])}")
        lines.append("")

        lines.append("## Top sensitive files touched")
        lines.append("")
        if context["top_paths"]:
            lines.append("| Path | Times touched |")
            lines.append("|------|---------------|")
            for p in context["top_paths"]:
                lines.append(f"| `{p['path']}` | {p['count']} |")
        else:
            lines.append("_No sensitive files touched._")
        lines.append("")

        lines.append(f"## Timeline (last {len(context['timeline'])} events)")
        lines.append("")
        if context["timeline"]:
            lines.append("| Time (UTC) | Type | Source | Destination | Dest class | Sensitive |")
            lines.append("|------------|------|--------|-------------|------------|-----------|")
            for e in context["timeline"]:
                lines.append(
                    f"| {e['ts_utc']} | {e['event_type']} | `{e['src_path']}` | "
                    f"`{e['dest_path'] or '-'}` | {e['dest_class']} | "
                    f"{'YES' if e['is_sensitive'] else ''} |"
                )
        else:
            lines.append("_No events._")
        lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    def generate(
        self, out_dir: Optional[str] = None, context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, str]:
        """Write timestamped HTML + MD files; return ``{"html": ..., "md": ...}``."""
        context = context or self.collect()
        out_dir = out_dir or self.config.report_dir
        os.makedirs(out_dir, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_path = os.path.join(out_dir, f"sftms_report_{stamp}.html")
        md_path = os.path.join(out_dir, f"sftms_report_{stamp}.md")
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(self.render_html(context))
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(self.render_markdown(context))
        return {"html": html_path, "md": md_path}
