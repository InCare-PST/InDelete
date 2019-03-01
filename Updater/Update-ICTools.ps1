<# This is to update ICTools and place in Modules Directory #>
Function Update-ICTools {
  BEGIN{
$url = https://raw.githubusercontent.com/InCare-PST/ICTools/master/Modules/ICTools/ICTools-JTG.psm1
$ictpath = "$Home\Documents\WindowsPowerShell\Modules \ICTools"
$psp.test = Test-Path $Profile
$psp = New-Item –Path $Profile –Type File –Force
$archive = "$Home\Documents\WindowsPowerShell "
$file = "$ictpath\ICTools.psm1"
$bakfile = "$ictpath\ICtools.bak"
$temp = "$ictpath\ICTools.temp.psm1"
$webclient = New-Object System.Net.WebClient
}
Process{
#Make Directories

if(!(Test-Path -Path $ictpath)){New-Item -Path $ictpath -Type Directory -Force}
if(!$psp.test){$psp}
#if(!(Test-Path -Path $archive)){New-Item -Path $archive}

if($file){Rename-Item -Path $file -NewName $bakfile -Force}

$webclient.downloadfile($url, $file)
}
End{Write-host "File Updated"}
<#

$webclient.downloadfile($url, $temp)
$V1 = get-content
$V2 = get-content

try{
    if($V2 -GT $V1){
      Write-Host -ForegroundColor Green ("An Update has been found...")
      Write-Host -ForegroundColor Green ("Retreiving Update... Please wait")
      Rename-Item -Path $file -NewName $archive\$($Date.tostring("dd-MM-yyyy")+" "+"ICTools.bak") -Force
      Rename-Item -Path $temp -NewName $file -Force
    }else{
      Write-Host -ForegroundColor Green ("You already have the latest version")
      Remove-item -Path $temp -Force
         }
   }catch{
     Write-Host -ForegroundColor Red ("There has been an error retreiving update")
   }

#>
}
Update-ICTools
