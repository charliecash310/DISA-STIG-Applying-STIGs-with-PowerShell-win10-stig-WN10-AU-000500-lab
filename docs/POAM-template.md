# POA&M Entry – WN10-AU-000500

**System:** <WIN-10-Target-G / VM ID 'cd015a7d-a927-49c6-896a-67d4a4886ef4'>  
**Control:** WN10-AU-000500 – Application log size >= 32768 KB  
**Severity:** CAT II  
**Scanner:** Tenable (scan id/date)

## Finding
Application log max size below 32768 KB.

## Evidence
- Screenshot: Tenable FAIL
- Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\MaxSize`
- Live channel: `wevtutil gl Application` shows maxSize < 32768

## Risk
Early log rollover → lost evidence, reduced auditability.

## Remediation
Run `scripts/Fix-StigWN10-AU-000500.ps1`.

## Validation
- `Verify-EventLogSize.ps1` output attached
- Tenable re-scan: PASS (screenshot)

## Residual Risk
None.
