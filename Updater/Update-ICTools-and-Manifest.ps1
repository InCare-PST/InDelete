<#
DO NOT USE; THIS IS NOT READY AND WILL BREAK EVERYTHING!!!!

This is to update ICTools and place in Modules Directory


#>
Function Update-ICTools {

BEGIN{

    $url = "https://raw.githubusercontent.com/InCare-PST/ICTools/master/Modules/ICTools/ICTools.psm1"
    $ictpath = "$Home\Documents\WindowsPowerShell\Modules\ICTools"
    $psptest = Test-Path $Profile
    $psp = New-Item –Path $Profile –Type File –Force
    $file = "$ictpath\ICTools.psm1"
    $bakfile = "$ictpath\ICtools.bak"
    $temp = "$ictpath\ICTools.temp.psm1"
    $webclient = New-Object System.Net.WebClient
}
Process{
#Make Directories

if(!(Test-Path -Path $ictpath)){New-Item -Path $ictpath -Type Directory -Force}
if(!$psptest){$psp}
#if(!(Test-Path -Path $archive)){New-Item -Path $archive}

if(Test-Path -Path $bakfile){Remove-Item -Path $bakfile -Force}
if(Test-Path -Path $file){Rename-Item -Path $file -NewName $bakfile -Force}

$webclient.downloadfile($url, $file)
}
End{
#Planned for Version number check to temp and only update if not latest version
write-host -ForegroundColor Green("Reloading Powershell to access updated module")
start-sleep -seconds 3
start-process PowerShell
stop-process -Id $PID
}
#[Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls11, Tls, Ssl3"
#$ictpath = "$Home\Documents\WindowsPowerShell\Modules\ICTools"
$releaseurl = "https://github.com/InCare-PST/ICTools/releases/latest"
$Version = (Invoke-WebRequest $releaseurl -UseBasicParsing).links | Where {$_.Title -NotMatch "GitHub" -and $_.Title -GT "0"} | Select -Unique Title
$ProjectUri = "https://github.com/InCare-PST/ICTools"
$tempobj = (Get-Content -Path C:\Users\administrator.GILESMTG\Documents\WindowsPowerShell\Modules\ICTools\ICTools.psm1 -Tail 1).trim("Export-ModuleMember -Function")
$cmdexports += $tempobj -split "," -join '" ,"'
new-modulemanifest -Path $ictpath\ICTools.psd1 -CompanyName "InCare Technologies" -Author "ICT Team" -ModuleVersion $version.title -ProjectUri $ProjectUri -FunctionsToExport @("*")
import-module ICTools
#End of Function
}
Update-ICTools
