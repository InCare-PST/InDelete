Function Get-LastLogon{
[cmdletbinding()]
    param(
        [string]$Path="C:\temp",
        [switch]$Export,
        [string]$Days=60
        )
$getcomp = Get-ADComputer -Filter * -Properties LastLogonDate
$date = (get-date).AddDays(-$Days)

if($Export){
  $getcomp  | where lastlogondate -GE $date | Export-Csv -Path $Path\($Date.tostring("dd-MM-yyyy")+" "+"ActiveComputers.csv")
}else{
  $getcomp  | where lastlogondate -GE $date | select Name,LastLogonDate | sort LastLogonDate -Descending | ft -AutoSize
}
}

Get-LastLogon
