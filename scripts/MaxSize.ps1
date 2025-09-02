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
