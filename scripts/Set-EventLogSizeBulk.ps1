<#
.SYNOPSIS
  Apply minimum sizes + retention to multiple core logs.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
  [string[]]$Logs = @('Application','Security','System'),
  [int]$MinKB = 32768
)

function Require-Admin {
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  $p =New-Object Security.Principal.WindowsPrincipal($id)
  if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw "Run as Administrator."
  }
}

Require-Admin

foreach($log in $Logs){
  $polPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\$log"
  New-Item -Path $polPath -Force | Out-Null
  New-ItemProperty -Path $polPath -Name MaxSize -PropertyType DWord -Value $MinKB -Force | Out-Null

  if($PSCmdlet.ShouldProcess($log, "wevtutil sl /ms:$MinKB /rt:false /ab:false")){
    wevtutil sl $log /ms:$MinKB | Out-Null
    wevtutil sl $log /rt:false /ab:false | Out-Null
  }
  Write-Host "Set $log to >= $MinKB KB and overwrite-as-needed."
}
