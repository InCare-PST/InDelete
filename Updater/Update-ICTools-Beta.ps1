<# This is to update ICTools and place in Modules Directory #>
Function Update-ICToolsBeta {

BEGIN{

    $url = "https://raw.githubusercontent.com/InCare-PST/ICTools/master/Modules/ICTools/ICTools-Beta.psm1"
    $ictpath = "$Home\Documents\WindowsPowerShell\Modules\ICTools-Beta"
    $psptest = Test-Path $Profile
    $psp = New-Item –Path $Profile –Type File –Force
    $file = "$ictpath\ICTools-Beta.psm1"
    $bakfile = "$ictpath\ICtools-Beta.bak"
    $temp = "$ictpath\ICTools-Beta.temp.psm1"
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
#start-process PowerShell
#stop-process -Id $PID
remove-module ICTools-Beta
import-module ICTools-Beta
}

#End of Function
}
Update-ICTools
