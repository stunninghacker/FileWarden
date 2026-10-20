# SFTMS - Secure File Transfer Monitoring System

A cross-platform (Windows + Linux) **blue-team / DLP toolkit** in Python that:

- monitors configured directories recursively for **create / modify / move / delete** events,
- detects **unauthorised transfers** of sensitive files to **USB / network / cloud** targets,
- detects **bulk exfiltration** bursts,
- verifies file **integrity** via SHA-256 (or MD5) baselines and catches tampering,
- raises colour-coded **alerts** (console + log + database + optional desktop toast),
- produces a **timestamped HTML + Markdown audit report**.

```
sftms/
  config.yaml          # default configuration
  requirements.txt     # pinned dependencies
  README.md
  pyproject.toml       # optional: enables `pip install -e .` + the `sftms` command
  sftms/               # the package
    config.py  db.py  hashing.py  monitor.py  classifier.py
    authorizer.py  detectors.py  alerts.py  integrity.py
    reporter.py  cli.py  demo.py  __main__.py
  tests/               # pytest suite
  scripts/demo.py      # standalone demo launcher
```

## Install

```bash
# from the project root (the folder that contains config.yaml)
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux:    source .venv/bin/activate

pip install -r requirements.txt

# optional: get the `sftms` command on your PATH
pip install -e .
```

If you do **not** run `pip install -e .`, use `python -m sftms ...` in place of
`sftms ...` everywhere below.

## Configure (`config.yaml`)

| Key | Meaning |
|-----|---------|
| `watch_dirs` | directories to monitor recursively |
| `sensitive_dirs` | directories whose contents are always sensitive |
| `sensitive_patterns` | globs marking a file sensitive (e.g. `*.key`, `*secret*`, `payroll*.xlsx`) |
| `cloud_folder_patterns` | path fragments identifying cloud-sync folders (OneDrive/Dropbox/…) |
| `removable_path_patterns` | path patterns for USB / removable media |
| `network_path_patterns` | path patterns for network shares (SMB/NFS/UNC) |
| `ignore_patterns` | globs that are never logged (temp files, DB, VCS) |
| `hash_algorithm` | `sha256` (default) or `md5` |
| `bulk_threshold` | number of sensitive/external events that triggers a CRITICAL alert (default 50) |
| `bulk_window_seconds` | sliding time window for the bulk detector (default 60) |
| `db_path` / `log_dir` / `report_dir` | storage locations |
| `enable_desktop_notifications` | raise OS notifications via `plyer` when available |
| `enable_process_attribution` | best-effort PID/process attribution — **off by default** (see note below) |

Real detection uses `psutil` mount information plus the Windows `GetDriveTypeW`
API (via `ctypes`, fully guarded) and, on Linux, filesystem types
(`cifs`/`nfs`/`sshfs`…) and `/media` `/run/media` mount points. The explicit path
patterns let the same behaviour be demonstrated and tested without real hardware.

## Commands

```bash
# 1. Start live monitoring (Ctrl-C to stop)
sftms monitor

# 2. Create / refresh the integrity baseline for a directory
sftms baseline /path/to/protected/dir

# 3. Full integrity scan vs the baseline (exit code 1 on modifications/deletions)
sftms verify

# 4. Generate the HTML + Markdown audit report
sftms report                 # into config report_dir
sftms report --out ./reports # into a custom directory

# 5. Run the scripted demo (fires every alert type)
sftms demo

# 6. Quick database summary
sftms stats
```

Global option: `--config PATH` selects a non-default configuration file.

## Alert severities

| Severity | Raised when |
|----------|-------------|
| `LOW` | a sensitive file is touched on local storage |
| `HIGH` | a sensitive file is copied/moved to a **removable, network or cloud** target |
| `CRITICAL` | more than `bulk_threshold` sensitive/external events within `bulk_window_seconds` (possible exfiltration) |
| `INTEGRITY` | a baselined file's hash no longer matches (tamper / corruption / deletion) |

## Run the demo

```bash
sftms demo
# or
python scripts/demo.py
```

The demo builds a temporary sandbox, starts the monitor in the background and
then drives one of each scenario so every alert type fires:

1. **HIGH** – copy `payroll_2024.xlsx` to a simulated **Dropbox** folder
2. **HIGH** – copy `id_rsa.key` to a simulated **USB** drive
3. **HIGH** – copy `api_credentials.pem` to a simulated **SMB share**
4. **LOW** – create + modify a sensitive file on local storage
5. **INTEGRITY** – tamper with a baselined file (`secrets.env`)
6. **CRITICAL** – rapidly move 60 files to the USB drive (bulk exfiltration)

It finishes by running `verify` and auto-generating the report. The sandbox
path, `alerts.log`, report paths and the alert histogram are printed at the end
so they can be inspected and screenshotted.

A pre-generated sample from a real demo run is committed under `docs/`:
`docs/sample_report.html`, `docs/sample_report.md` and `docs/sample_alerts.log`.

## Tests

```bash
pytest -q
```

Covers hashing (SHA-256/MD5, chunked + large files, missing files),
classification (dir vs pattern, case-insensitivity), authorisation
(LOW/HIGH/CRITICAL logic, bulk windows) and integrity
(baseline, intact/modified/deleted/added, on-modify tamper detection).

## Notes & limitations

- Filesystem notifications carry **no PID**. Process attribution is therefore
  best-effort: a background daemon thread scans `psutil` open files, but the scan
  is expensive (~seconds per path on Windows) and rarely resolves for
  short-lived copies, so it is **disabled by default**
  (`enable_process_attribution: false`). It never blocks the monitor; when it
  cannot resolve, the event is still logged with `process_name="unknown"`. The
  demo runs with it off for speed/determinism.
- Only regular **file** events are logged (directory events are ignored) to
  keep the audit trail file-focused.
- The report's integrity section is a read-only `verify` pass (it does not raise
  duplicate alerts).
