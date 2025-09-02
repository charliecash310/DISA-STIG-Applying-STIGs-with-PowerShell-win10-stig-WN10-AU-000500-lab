<#
.SYNOPSIS
  Remediate STIG WN10-AU-000500: Application log >= 32768 KB
  Sets both policy key and live channel; idempotent.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
  [int]$MinKB = 32768
)

function Require-Admin {
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  $p =New-Object Security.Principal.WindowsPrincipal($id)
  if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw "Run as Administrator."
  }
}

function Get-LogInfo($name){
  $raw = wevtutil gl $name 2>$null
  if(-not $raw){ throw "Cannot query $name." }
  [pscustomobject]@{
    maxSize   = [int](([regex]'maxSize:\s*(\d+)').Match(($raw -join "`n")).Groups[1].Value)
    retention = ([regex]'retention:\s*(\w+)').Match(($raw -join "`n")).Groups[1].Value.ToLower()
    autoBackup= ([regex]'autoBackup:\s*(\w+)').Match(($raw -join "`n")).Groups[1].Value.ToLower()
  }
}

Require-Admin

$polPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
$polName = 'MaxSize'

New-Item -Path $polPath -Force | Out-Null
$current = (Get-ItemProperty -Path $polPath -Name $polName -ErrorAction SilentlyContinue).$polName

if(-not $current -or $current -lt $MinKB){
  if($PSCmdlet.ShouldProcess($polPath, "Set $polName=$MinKB")){
    New-ItemProperty -Path $polPath -Name $polName -PropertyType DWord -Value $MinKB -Force | Out-Null
  }
}

# live channel
if($PSCmdlet.ShouldProcess("Application", "wevtutil sl /ms:$MinKB /rt:false /ab:false")){
  wevtutil sl Application /ms:$MinKB | Out-Null
  wevtutil sl Application /rt:false /ab:false | Out-Null      # overwrite as needed, no autobackup
}

$live = Get-LogInfo Application
$policySet = (Get-ItemProperty -Path $polPath -Name $polName).$polName

Write-Host "Policy MaxSize: $policySet KB (required >= $MinKB)"
Write-Host "Live MaxSize:   $($live.maxSize) KB (required >= $MinKB)"
Write-Host "Retention:      $($live.retention)  (false=overwrite as needed)"
Write-Host "AutoBackup:     $($live.autoBackup) (false)"
