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
- `scripts/MaxSize.ps1` - original script for elevated privileges
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


<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Grisham DelRosario
    LinkedIn        : linkedin.com/in/grishamdelrosario/
    GitHub          : github.com/charliecash310
    Date Created    : 2025-09-01
    Last Modified   : 2025-09-01
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000500

.TESTED ON
    Date(s) Tested  : 2025-09-01
    Tested By       : Grisham DelRosario
    Systems Tested  : Windows 10
    PowerShell Ver. : 5.1.19041.6216

.USAGE
    Use Powershell ISE or VSCode to run the script.
    Example syntax:
    PS C:\> .\MaxSize.ps1 

#>

# --- STIG: WN10-AU-000500  (Application log >= 32768 KB) ---

$minKB = 32768
$polPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
$polName = 'MaxSize'

# 1) Ensure the policy registry path/value exists and is >= 32768
New-Item -Path $polPath -Force | Out-Null
$current = (Get-ItemProperty -Path $polPath -Name $polName -ErrorAction SilentlyContinue).$polName
if (-not $current -or $current -lt $minKB) {
    New-ItemProperty -Path $polPath -Name $polName -PropertyType DWord -Value $minKB -Force | Out-Null
}

# 2) Apply immediately to the live channel (so you don't have to wait for gpupdate/reboot)
wevtutil sl Application /ms:$minKB | Out-Null

# (Optional but recommended) ensure retention is "Overwrite events as needed"
wevtutil sl Application /rt:false /ab:false | Out-Null

# 3) Verify
$policySet = (Get-ItemProperty -Path $polPath -Name $polName).$polName
$liveInfo  = wevtutil gl Application
$liveSize  = ($liveInfo | Select-String -Pattern 'maxSize:\s*(\d+)').Matches.Groups[1].Value

Write-Host "Policy MaxSize (KB): $policySet (required >= $minKB)"
Write-Host "Live channel maxSize (KB): $liveSize (required >= $minKB)"
Write-Host "Retention:" (($liveInfo | Select-String 'retention:\s*(\w+)').Matches.Groups[1].Value) " (false = overwrite as needed)"

