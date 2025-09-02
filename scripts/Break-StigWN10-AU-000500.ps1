<#
.SYNOPSIS
  Force non-compliance for STIG WN10-AU-000500 (lab/demo).
#>

[CmdletBinding()]
param(
  [int]$NonCompliantKB = 1024
)

function Require-Admin {
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  $p =New-Object Security.Principal.WindowsPrincipal($id)
  if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw "Run as Administrator."
  }
}

$polPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
$polName = 'MaxSize'

Require-Admin

New-Item -Path $polPath -Force | Out-Null
New-ItemProperty -Path $polPath -Name $polName -PropertyType DWord -Value $NonCompliantKB -Force | Out-Null

# apply immediately to live channel
wevtutil sl Application /ms:$NonCompliantKB | Out-Null

Write-Host "Applied non-compliant size: $NonCompliantKB KB (policy + live)."
