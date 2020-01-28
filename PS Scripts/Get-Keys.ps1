function Get-Keys{
<# Function Future Information
#>

    Import-module ActiveDirectory
    $date = (get-date).AddDays(-60)
    $LogDir = "C:\Temp"
    $computers = Get-ADComputer -Filter * -Properties LastLogonDate,OperatingSystem | where {$_.lastlogondate -GE $date}
    $OnlineComputers = @()
    $Workstations = @()

#Create Log Location Phase
    if(!$LogDir) {New-Item -Path "c:\Temp" -Name "logfiles" -ItemType "directory"}

#Online Computer Phase
    ForEach ($comp in $computers) {
        if (Test-Connection -ComputerName $comp.name -Count 1 -Quiet) {
            $OnlineComputers += $comp
        }
    }
    $workstations = $OnlineComputers

#Key Phase
    $KeyCSV = @()
    ForEach ($workstaion in $workstations){
      $TempKey = @{
          ComputerName = $workstation.name
          OS = $workstation.OperatingSystem
          LastLogon = $workstation.LastLogonDate
          ProductKey = (Get-WmiObject -query ‘select * from SoftwareLicensingService’).OA3xOriginalProductKey
      }
      $KeyObj = New-Object -TypeName psobject -Property $TempKey
      $KeyCSV += $KeyObj
    }


$KeyCSV | Export-CSV -path $Logdir\Keys.csv -NoTypeInformation



}
Get-Keys 
