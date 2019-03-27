<#This script sets all local Network Profile Types to Private

Ideas for furture use:
1) Delete all profiles and recreate the one that is currently being used, then set it to private.

#>
function Set-FirewallPrivate{

$alpha = @()
$bravo = @()
$alpha = (Get-childitem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" | Get-ItemProperty -Name Category | Where Category -eq 0).pspath
$bravo += $alpha.trim("Microsoft.PowerShell.Core\")

foreach($b in $bravo){
set-itemproperty -path $b -Name Category -Value 1 -ErrorAction SilentlyContinue
set-itemproperty -path $b -Name CategoryType -Value 0 -ErrorAction SilentlyContinue
}
}

Set-FirewallPrivate
