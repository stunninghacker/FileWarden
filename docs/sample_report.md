# Secure File Transfer Monitoring System - Audit Report

- Generated (UTC): 2026-10-20T05:04:47Z
- Generated (local): 2026-10-20 10:34:47
- Hash algorithm: `sha256`

## Summary

- Total events: **250**
- Sensitive events: **10**
- Total alerts: **7**
- Baselined files: **5**
- Integrity failures: **1**

## Events by type

| Event type | Count |
|------------|-------|
| created | 124 |
| deleted | 60 |
| modified | 66 |

## Alerts by severity

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| INTEGRITY | 1 |
| HIGH | 3 |
| LOW | 2 |

## Violations / alerts

| Time (UTC) | Severity | Title | Source | Destination | Detail |
|------------|----------|-------|--------|-------------|--------|
| 2026-10-20T05:04:45.313Z | CRITICAL | Possible bulk exfiltration (CRITICAL) | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_47.txt` | `-` | 50 file events targeting 'removable:c:\users\saksh\appdata\local\temp\sftms_verify\sandbox\usb_drive' within 60s (threshold 50) - possible exfiltration |
| 2026-10-20T05:04:41.741Z | INTEGRITY | Integrity violation: file modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\sensitive\secrets.env` | `-` | secrets.env hash changed (baseline 866e8a9c822b... != current cd729c921263...) |
| 2026-10-20T05:04:41.704Z | LOW | Sensitive file accessed | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\sensitive\secrets.env` | `-` | sensitive file modified on local storage (inside sensitive directory 'c:/users/saksh/appdata/local/temp/sftms_verify/sandbox/sensitive') |
| 2026-10-20T05:04:39.699Z | LOW | Sensitive file accessed | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\sensitive\confidential_offer.pdf` | `-` | sensitive file created on local storage (inside sensitive directory 'c:/users/saksh/appdata/local/temp/sftms_verify/sandbox/sensitive') |
| 2026-10-20T05:04:38.493Z | HIGH | Sensitive file transferred to external location | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\smb_share\api_credentials.pem` | `-` | sensitive file created to network destination (filename/path matches sensitive pattern '*.pem') |
| 2026-10-20T05:04:37.289Z | HIGH | Sensitive file transferred to external location | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\id_rsa.key` | `-` | sensitive file created to removable destination (filename/path matches sensitive pattern '*.key') |
| 2026-10-20T05:04:36.084Z | HIGH | Sensitive file transferred to external location | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\Dropbox\payroll_2024.xlsx` | `-` | sensitive file created to cloud destination (filename/path matches sensitive pattern 'payroll*') |

## Integrity results

- Intact: 4
- Modified: 1
- Deleted: 0
- Added: 1

## Top sensitive files touched

| Path | Times touched |
|------|---------------|
| `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\sensitive\confidential_offer.pdf` | 3 |
| `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\id_rsa.key` | 2 |
| `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\smb_share\api_credentials.pem` | 2 |
| `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\Dropbox\payroll_2024.xlsx` | 2 |
| `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\sensitive\secrets.env` | 1 |

## Timeline (last 250 events)

| Time (UTC) | Type | Source | Destination | Dest class | Sensitive |
|------------|------|--------|-------------|------------|-----------|
| 2026-10-20T05:04:36.075Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\Dropbox\payroll_2024.xlsx` | `-` | cloud | YES |
| 2026-10-20T05:04:36.093Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\Dropbox\payroll_2024.xlsx` | `-` | cloud | YES |
| 2026-10-20T05:04:37.282Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\id_rsa.key` | `-` | removable | YES |
| 2026-10-20T05:04:37.302Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\id_rsa.key` | `-` | removable | YES |
| 2026-10-20T05:04:38.487Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\smb_share\api_credentials.pem` | `-` | network | YES |
| 2026-10-20T05:04:38.503Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\smb_share\api_credentials.pem` | `-` | network | YES |
| 2026-10-20T05:04:39.691Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\sensitive\confidential_offer.pdf` | `-` | local | YES |
| 2026-10-20T05:04:39.706Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\sensitive\confidential_offer.pdf` | `-` | local | YES |
| 2026-10-20T05:04:40.493Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\sensitive\confidential_offer.pdf` | `-` | local | YES |
| 2026-10-20T05:04:41.697Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\sensitive\secrets.env` | `-` | local | YES |
| 2026-10-20T05:04:43.199Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_00.txt` | `-` | local |  |
| 2026-10-20T05:04:43.208Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_00.txt` | `-` | local |  |
| 2026-10-20T05:04:43.224Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_01.txt` | `-` | local |  |
| 2026-10-20T05:04:43.234Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_01.txt` | `-` | local |  |
| 2026-10-20T05:04:43.253Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_02.txt` | `-` | local |  |
| 2026-10-20T05:04:43.265Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_02.txt` | `-` | local |  |
| 2026-10-20T05:04:43.284Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_03.txt` | `-` | local |  |
| 2026-10-20T05:04:43.296Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_03.txt` | `-` | local |  |
| 2026-10-20T05:04:43.315Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_04.txt` | `-` | local |  |
| 2026-10-20T05:04:43.323Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_04.txt` | `-` | local |  |
| 2026-10-20T05:04:43.343Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_05.txt` | `-` | local |  |
| 2026-10-20T05:04:43.351Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_05.txt` | `-` | local |  |
| 2026-10-20T05:04:43.365Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_06.txt` | `-` | local |  |
| 2026-10-20T05:04:43.370Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_06.txt` | `-` | local |  |
| 2026-10-20T05:04:43.385Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_07.txt` | `-` | local |  |
| 2026-10-20T05:04:43.392Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_07.txt` | `-` | local |  |
| 2026-10-20T05:04:43.406Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_08.txt` | `-` | local |  |
| 2026-10-20T05:04:43.414Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_08.txt` | `-` | local |  |
| 2026-10-20T05:04:43.427Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_09.txt` | `-` | local |  |
| 2026-10-20T05:04:43.433Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_09.txt` | `-` | local |  |
| 2026-10-20T05:04:43.447Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_10.txt` | `-` | local |  |
| 2026-10-20T05:04:43.453Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_10.txt` | `-` | local |  |
| 2026-10-20T05:04:43.467Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_11.txt` | `-` | local |  |
| 2026-10-20T05:04:43.473Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_11.txt` | `-` | local |  |
| 2026-10-20T05:04:43.487Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_12.txt` | `-` | local |  |
| 2026-10-20T05:04:43.495Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_12.txt` | `-` | local |  |
| 2026-10-20T05:04:43.505Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_13.txt` | `-` | local |  |
| 2026-10-20T05:04:43.513Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_13.txt` | `-` | local |  |
| 2026-10-20T05:04:43.523Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_14.txt` | `-` | local |  |
| 2026-10-20T05:04:43.531Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_14.txt` | `-` | local |  |
| 2026-10-20T05:04:43.544Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_15.txt` | `-` | local |  |
| 2026-10-20T05:04:43.550Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_15.txt` | `-` | local |  |
| 2026-10-20T05:04:43.563Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_16.txt` | `-` | local |  |
| 2026-10-20T05:04:43.569Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_16.txt` | `-` | local |  |
| 2026-10-20T05:04:43.582Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_17.txt` | `-` | local |  |
| 2026-10-20T05:04:43.588Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_17.txt` | `-` | local |  |
| 2026-10-20T05:04:43.601Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_18.txt` | `-` | local |  |
| 2026-10-20T05:04:43.606Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_18.txt` | `-` | local |  |
| 2026-10-20T05:04:43.618Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_19.txt` | `-` | local |  |
| 2026-10-20T05:04:43.626Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_19.txt` | `-` | local |  |
| 2026-10-20T05:04:43.641Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_20.txt` | `-` | local |  |
| 2026-10-20T05:04:43.682Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_20.txt` | `-` | local |  |
| 2026-10-20T05:04:43.719Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_21.txt` | `-` | local |  |
| 2026-10-20T05:04:43.730Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_21.txt` | `-` | local |  |
| 2026-10-20T05:04:43.749Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_22.txt` | `-` | local |  |
| 2026-10-20T05:04:43.756Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_22.txt` | `-` | local |  |
| 2026-10-20T05:04:43.771Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_23.txt` | `-` | local |  |
| 2026-10-20T05:04:43.781Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_23.txt` | `-` | local |  |
| 2026-10-20T05:04:43.794Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_24.txt` | `-` | local |  |
| 2026-10-20T05:04:43.800Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_24.txt` | `-` | local |  |
| 2026-10-20T05:04:43.813Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_25.txt` | `-` | local |  |
| 2026-10-20T05:04:43.820Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_25.txt` | `-` | local |  |
| 2026-10-20T05:04:43.834Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_26.txt` | `-` | local |  |
| 2026-10-20T05:04:43.845Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_26.txt` | `-` | local |  |
| 2026-10-20T05:04:43.856Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_27.txt` | `-` | local |  |
| 2026-10-20T05:04:43.864Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_27.txt` | `-` | local |  |
| 2026-10-20T05:04:43.879Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_28.txt` | `-` | local |  |
| 2026-10-20T05:04:43.885Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_28.txt` | `-` | local |  |
| 2026-10-20T05:04:43.897Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_29.txt` | `-` | local |  |
| 2026-10-20T05:04:43.904Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_29.txt` | `-` | local |  |
| 2026-10-20T05:04:43.918Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_30.txt` | `-` | local |  |
| 2026-10-20T05:04:43.926Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_30.txt` | `-` | local |  |
| 2026-10-20T05:04:43.940Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_31.txt` | `-` | local |  |
| 2026-10-20T05:04:43.949Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_31.txt` | `-` | local |  |
| 2026-10-20T05:04:43.966Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_32.txt` | `-` | local |  |
| 2026-10-20T05:04:43.972Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_32.txt` | `-` | local |  |
| 2026-10-20T05:04:43.986Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_33.txt` | `-` | local |  |
| 2026-10-20T05:04:43.994Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_33.txt` | `-` | local |  |
| 2026-10-20T05:04:44.008Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_34.txt` | `-` | local |  |
| 2026-10-20T05:04:44.016Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_34.txt` | `-` | local |  |
| 2026-10-20T05:04:44.029Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_35.txt` | `-` | local |  |
| 2026-10-20T05:04:44.034Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_35.txt` | `-` | local |  |
| 2026-10-20T05:04:44.048Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_36.txt` | `-` | local |  |
| 2026-10-20T05:04:44.054Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_36.txt` | `-` | local |  |
| 2026-10-20T05:04:44.069Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_37.txt` | `-` | local |  |
| 2026-10-20T05:04:44.077Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_37.txt` | `-` | local |  |
| 2026-10-20T05:04:44.088Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_38.txt` | `-` | local |  |
| 2026-10-20T05:04:44.097Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_38.txt` | `-` | local |  |
| 2026-10-20T05:04:44.109Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_39.txt` | `-` | local |  |
| 2026-10-20T05:04:44.115Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_39.txt` | `-` | local |  |
| 2026-10-20T05:04:44.128Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_40.txt` | `-` | local |  |
| 2026-10-20T05:04:44.135Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_40.txt` | `-` | local |  |
| 2026-10-20T05:04:44.149Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_41.txt` | `-` | local |  |
| 2026-10-20T05:04:44.155Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_41.txt` | `-` | local |  |
| 2026-10-20T05:04:44.169Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_42.txt` | `-` | local |  |
| 2026-10-20T05:04:44.177Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_42.txt` | `-` | local |  |
| 2026-10-20T05:04:44.188Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_43.txt` | `-` | local |  |
| 2026-10-20T05:04:44.196Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_43.txt` | `-` | local |  |
| 2026-10-20T05:04:44.206Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_44.txt` | `-` | local |  |
| 2026-10-20T05:04:44.214Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_44.txt` | `-` | local |  |
| 2026-10-20T05:04:44.227Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_45.txt` | `-` | local |  |
| 2026-10-20T05:04:44.233Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_45.txt` | `-` | local |  |
| 2026-10-20T05:04:44.248Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_46.txt` | `-` | local |  |
| 2026-10-20T05:04:44.254Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_46.txt` | `-` | local |  |
| 2026-10-20T05:04:44.270Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_47.txt` | `-` | local |  |
| 2026-10-20T05:04:44.278Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_47.txt` | `-` | local |  |
| 2026-10-20T05:04:44.290Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_48.txt` | `-` | local |  |
| 2026-10-20T05:04:44.297Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_48.txt` | `-` | local |  |
| 2026-10-20T05:04:44.309Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_49.txt` | `-` | local |  |
| 2026-10-20T05:04:44.315Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_49.txt` | `-` | local |  |
| 2026-10-20T05:04:44.327Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_50.txt` | `-` | local |  |
| 2026-10-20T05:04:44.332Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_50.txt` | `-` | local |  |
| 2026-10-20T05:04:44.347Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_51.txt` | `-` | local |  |
| 2026-10-20T05:04:44.355Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_51.txt` | `-` | local |  |
| 2026-10-20T05:04:44.372Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_52.txt` | `-` | local |  |
| 2026-10-20T05:04:44.384Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_52.txt` | `-` | local |  |
| 2026-10-20T05:04:44.400Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_53.txt` | `-` | local |  |
| 2026-10-20T05:04:44.410Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_53.txt` | `-` | local |  |
| 2026-10-20T05:04:44.429Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_54.txt` | `-` | local |  |
| 2026-10-20T05:04:44.435Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_54.txt` | `-` | local |  |
| 2026-10-20T05:04:44.448Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_55.txt` | `-` | local |  |
| 2026-10-20T05:04:44.454Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_55.txt` | `-` | local |  |
| 2026-10-20T05:04:44.466Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_56.txt` | `-` | local |  |
| 2026-10-20T05:04:44.475Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_56.txt` | `-` | local |  |
| 2026-10-20T05:04:44.489Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_57.txt` | `-` | local |  |
| 2026-10-20T05:04:44.498Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_57.txt` | `-` | local |  |
| 2026-10-20T05:04:44.512Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_58.txt` | `-` | local |  |
| 2026-10-20T05:04:44.518Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_58.txt` | `-` | local |  |
| 2026-10-20T05:04:44.531Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_59.txt` | `-` | local |  |
| 2026-10-20T05:04:44.538Z | modified | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_59.txt` | `-` | local |  |
| 2026-10-20T05:04:44.553Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_00.txt` | `-` | local |  |
| 2026-10-20T05:04:44.561Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_00.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.569Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_01.txt` | `-` | local |  |
| 2026-10-20T05:04:44.578Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_01.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.585Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_02.txt` | `-` | local |  |
| 2026-10-20T05:04:44.594Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_02.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.599Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_03.txt` | `-` | local |  |
| 2026-10-20T05:04:44.606Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_03.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.615Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_04.txt` | `-` | local |  |
| 2026-10-20T05:04:44.622Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_04.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.631Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_05.txt` | `-` | local |  |
| 2026-10-20T05:04:44.639Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_05.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.648Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_06.txt` | `-` | local |  |
| 2026-10-20T05:04:44.655Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_06.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.662Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_07.txt` | `-` | local |  |
| 2026-10-20T05:04:44.670Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_07.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.678Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_08.txt` | `-` | local |  |
| 2026-10-20T05:04:44.686Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_08.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.695Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_09.txt` | `-` | local |  |
| 2026-10-20T05:04:44.701Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_09.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.708Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_10.txt` | `-` | local |  |
| 2026-10-20T05:04:44.715Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_10.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.722Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_11.txt` | `-` | local |  |
| 2026-10-20T05:04:44.731Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_11.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.738Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_12.txt` | `-` | local |  |
| 2026-10-20T05:04:44.747Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_12.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.753Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_13.txt` | `-` | local |  |
| 2026-10-20T05:04:44.763Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_13.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.768Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_14.txt` | `-` | local |  |
| 2026-10-20T05:04:44.776Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_14.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.782Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_15.txt` | `-` | local |  |
| 2026-10-20T05:04:44.789Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_15.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.797Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_16.txt` | `-` | local |  |
| 2026-10-20T05:04:44.803Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_16.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.810Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_17.txt` | `-` | local |  |
| 2026-10-20T05:04:44.817Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_17.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.822Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_18.txt` | `-` | local |  |
| 2026-10-20T05:04:44.831Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_18.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.835Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_19.txt` | `-` | local |  |
| 2026-10-20T05:04:44.846Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_19.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.851Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_20.txt` | `-` | local |  |
| 2026-10-20T05:04:44.860Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_20.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.865Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_21.txt` | `-` | local |  |
| 2026-10-20T05:04:44.872Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_21.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.881Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_22.txt` | `-` | local |  |
| 2026-10-20T05:04:44.887Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_22.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.897Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_23.txt` | `-` | local |  |
| 2026-10-20T05:04:44.904Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_23.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.914Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_24.txt` | `-` | local |  |
| 2026-10-20T05:04:44.921Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_24.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.930Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_25.txt` | `-` | local |  |
| 2026-10-20T05:04:44.936Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_25.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.950Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_26.txt` | `-` | local |  |
| 2026-10-20T05:04:44.958Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_26.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.964Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_27.txt` | `-` | local |  |
| 2026-10-20T05:04:44.971Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_27.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.981Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_28.txt` | `-` | local |  |
| 2026-10-20T05:04:44.988Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_28.txt` | `-` | removable |  |
| 2026-10-20T05:04:44.997Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_29.txt` | `-` | local |  |
| 2026-10-20T05:04:45.006Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_29.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.015Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_30.txt` | `-` | local |  |
| 2026-10-20T05:04:45.022Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_30.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.031Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_31.txt` | `-` | local |  |
| 2026-10-20T05:04:45.039Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_31.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.047Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_32.txt` | `-` | local |  |
| 2026-10-20T05:04:45.054Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_32.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.062Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_33.txt` | `-` | local |  |
| 2026-10-20T05:04:45.069Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_33.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.077Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_34.txt` | `-` | local |  |
| 2026-10-20T05:04:45.083Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_34.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.088Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_35.txt` | `-` | local |  |
| 2026-10-20T05:04:45.098Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_35.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.105Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_36.txt` | `-` | local |  |
| 2026-10-20T05:04:45.115Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_36.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.121Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_37.txt` | `-` | local |  |
| 2026-10-20T05:04:45.131Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_37.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.138Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_38.txt` | `-` | local |  |
| 2026-10-20T05:04:45.149Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_38.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.155Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_39.txt` | `-` | local |  |
| 2026-10-20T05:04:45.165Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_39.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.172Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_40.txt` | `-` | local |  |
| 2026-10-20T05:04:45.182Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_40.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.189Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_41.txt` | `-` | local |  |
| 2026-10-20T05:04:45.200Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_41.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.212Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_42.txt` | `-` | local |  |
| 2026-10-20T05:04:45.219Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_42.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.231Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_43.txt` | `-` | local |  |
| 2026-10-20T05:04:45.239Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_43.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.248Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_44.txt` | `-` | local |  |
| 2026-10-20T05:04:45.257Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_44.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.264Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_45.txt` | `-` | local |  |
| 2026-10-20T05:04:45.272Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_45.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.280Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_46.txt` | `-` | local |  |
| 2026-10-20T05:04:45.288Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_46.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.296Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_47.txt` | `-` | local |  |
| 2026-10-20T05:04:45.304Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_47.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.323Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_48.txt` | `-` | local |  |
| 2026-10-20T05:04:45.332Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_48.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.339Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_49.txt` | `-` | local |  |
| 2026-10-20T05:04:45.348Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_49.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.355Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_50.txt` | `-` | local |  |
| 2026-10-20T05:04:45.366Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_50.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.372Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_51.txt` | `-` | local |  |
| 2026-10-20T05:04:45.382Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_51.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.388Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_52.txt` | `-` | local |  |
| 2026-10-20T05:04:45.396Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_52.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.403Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_53.txt` | `-` | local |  |
| 2026-10-20T05:04:45.412Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_53.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.417Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_54.txt` | `-` | local |  |
| 2026-10-20T05:04:45.426Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_54.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.432Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_55.txt` | `-` | local |  |
| 2026-10-20T05:04:45.440Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_55.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.447Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_56.txt` | `-` | local |  |
| 2026-10-20T05:04:45.455Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_56.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.463Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_57.txt` | `-` | local |  |
| 2026-10-20T05:04:45.475Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_57.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.482Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_58.txt` | `-` | local |  |
| 2026-10-20T05:04:45.492Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_58.txt` | `-` | removable |  |
| 2026-10-20T05:04:45.499Z | deleted | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\normal\bulk_59.txt` | `-` | local |  |
| 2026-10-20T05:04:45.509Z | created | `C:\Users\saksh\AppData\Local\Temp\sftms_verify\sandbox\usb_drive\bulk_59.txt` | `-` | removable |  |
