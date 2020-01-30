$serial=@()
$serials=@()
$key=@()
 Import-Module ActiveDirectory
    $date = (get-date).AddDays(-60)
    $computers = Get-ADComputer -Filter * -Properties * | where {$_.lastlogondate -GE $date}

Foreach($comp in $computers){

    $serial = Get-CimInstance Win32_Bios -ComputerName $comp.name -ErrorAction SilentlyContinue
    $key = get-wmiObject -query 'select * from SoftwareLicensingService' -ComputerName $comp.name -ErrorAction SilentlyContinue

    $tempobj = [PSCustomObject][ordered]@{
    Name = $Comp.name
    OS = $comp.OperatingSystem
    OSVersion = $comp.OperatingSystemVersion
    LastLogon = $comp.LastLogonDate
    Serial = $serial.SerialNumber
    ProductKey = $key.OA3xOriginalProductKey
    Date = (get-date)
  }
  #$LogObj = New-Object -TypeName psobject -Property $tempobj
  #$serials += $LogObj
  $serials += $tempObj
  }
  $serials | Export-Csv -Path c:\Temp\Serials_run4.csv -Append
