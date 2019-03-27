<#This script sets all local Network Profile Types to Private

Ideas for furture use:
1) Delete all profiles and recreate the one that is currently being used, then set it to private.

#>
function Set-FirewallPrivate{

  [cmdletbinding()]
  param(
      [switch]$NoRestart
    )

$alpha = @()
$bravo = @()
$alpha = (Get-childitem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" | Get-ItemProperty -Name Category | Where Category -eq 0).pspath
$bravo += $alpha.trim("Microsoft.PowerShell.Core\")

foreach($b in $bravo){
set-itemproperty -path $b -Name Category -Value 1 -ErrorAction SilentlyContinue
set-itemproperty -path $b -Name CategoryType -Value 0 -ErrorAction SilentlyContinue
write-host -Foregroundcolor Green (($(get-itemproperty -path $b -Name ProfileName).profilename) + ": has been updated"
}

if(!$NoRestart){
    Add-Type -AssemblyName PresentationCore,PresentationFramework
    $ButtonType = [System.Windows.MessageBoxButton]::YesNo
    $MessageIcon = [System.Windows.MessageBoxImage]::Exclamation
    $MessageBody = "This script requires a reboot, would you like to reboot now?"
    $MessageTitle = "Confirm Reboot"

    $Result = [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
    switch ($Result){
    "Yes" {
            write-host -ForegroundColor Green"Windows will restart in 30 seconds"
            start-sleep 30
            restart-computer -force
     }
    "No" {
    write-host -ForegroundColor Red "Please restart your computer later"

    }
  }
}
Set-FirewallPrivate
