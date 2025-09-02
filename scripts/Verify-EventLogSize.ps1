<#
.SYNOPSIS
  Verify event log size and policy for a given log (Application by default).
#>

[CmdletBinding()]
param(
  [string]$LogName = 'Application',
  [int]$MinKB = 32768,
  [string]$OutCsv
)

function Get-LogInfo($name){
  $raw = wevtutil gl $name 2>$null
  if(-not $raw){ throw "Cannot query $name." }
  [pscustomobject]@{
    LogName   = $name
    MaxSizeKB = [int](([regex]'maxSize:\s*(\d+)').Match(($raw -join "`n")).Groups[1].Value)
    Retention = ([regex]'retention:\s*(\w+)').Match(($raw -join "`n")).Groups[1].Value.ToLower()
    AutoBackup= ([regex]'autoBackup:\s*(\w+)').Match(($raw -join "`n")).Groups[1].Value.ToLower()
  }
}

$info = Get-LogInfo $LogName

# policy key path for Application; adjust if verifying other logs’ policy keys
$polPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\$LogName"
$polVal  = (Get-ItemProperty -Path $polPath -Name MaxSize -ErrorAction SilentlyContinue).MaxSize

$result = [pscustomobject]@{
  LogName          = $info.LogName
  LiveMaxSizeKB    = $info.MaxSizeKB
  PolicyMaxSizeKB  = $polVal
  Retention        = $info.Retention
  AutoBackup       = $info.AutoBackup
  MinRequiredKB    = $MinKB
  SizeCompliant    = ($info.MaxSizeKB -ge $MinKB)
  PolicyCompliant  = ($polVal -ge $MinKB)
  RetentionOK      = ($info.Retention -eq 'false')
  AutoBackupOK     = ($info.AutoBackup -eq 'false')
}

$result | Format-Table -Auto
if($OutCsv){ $result | Export-Csv -NoTypeInformation -Path $OutCsv }

if(-not ($result.SizeCompliant -and $result.PolicyCompliant -and $result.RetentionOK -and $result.AutoBackupOK)){
  exit 2
}
