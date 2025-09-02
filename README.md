# DISA-STIG-Applying-STIGs-with-PowerShell-win10-stig-WN10-AU-000500-lab
DISA STIG: Applying STIGs with PowerShell // win10-stig-WN10-AU-000500-lab

# Windows 10 STIG Lab — WN10-AU-000500
**Control:** The Application event log size must be configured to **32768 KB** (32 MB) or greater.  
**Goal:** Demonstrate full Fail → Fix → Verify cycle with PowerShell + Tenable.

## Why this matters
Small log sizes roll over quickly, losing evidence needed for incident response and audits.

## What this repo shows
- Break the control on purpose (for lab realism)
- Remediate idempotently via PowerShell (policy + live channel)
- Verify locally and with Tenable/Nessus

## Files
- `scripts/Break-StigWN10-AU-000500.ps1` – force non-compliance
- `scripts/Fix-StigWN10-AU-000500.ps1` – remediation (policy + live)
- `scripts/Verify-EventLogSize.ps1` – quick local audit (prints + CSV)
- `scripts/Set-EventLogSizeBulk.ps1` – apply min sizes to Application/Security/System
- `docs/POAM-template.md` – ready-to-fill remediation write-up
- `evidence/` – drop screenshots: Fail → Fix → Pass

## Quick start
> Run in an elevated PowerShell

```powershell
# 1) Break it (simulate failure)
.\scripts\Break-StigWN10-AU-000500.ps1

# (Optional) Local verify
.\scripts\Verify-EventLogSize.ps1 -LogName Application

# 2) Run your Tenable compliance scan → expect FAIL

# 3) Fix it
.\scripts\Fix-StigWN10-AU-000500.ps1

# 4) Verify locally
.\scripts\Verify-EventLogSize.ps1 -LogName Application -OutCsv .\evidence\verify-after-fix.csv

# 5) Re-run Tenable scan → expect PASS
