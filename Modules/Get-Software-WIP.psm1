Function Get-Software {

  [cmdletbinding(SupportsShouldProcess=$True)]

      param(

      [string]$Path="C:\temp",

      [switch]$Export,

      [switch]$Display,

      #[switch]$IsEnabled,


      )

Begin{

  $getcomputers = Get-ADComputer -Filter * -Properties LastLogonDate,OperatingSystem | where lastlogondate -GE $date
  $computers = ($getcomputers | select -ExpandProperty Name)
  $FileName = $Date.tostring("dd-MM-yyyy")+" "+"InactiveUsers.csv"
  $array = @()

Process{
  foreach($pc in $computers){

      $computername=$pc.computername

      #Define the variable to hold the location of Currently Installed Programs

      $UninstallKey=”SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall”


      #Create an instance of the Registry Object and open the HKLM base key

      $reg=[microsoft.win32.registrykey]::OpenRemoteBaseKey(‘LocalMachine’,$computername)

      #Drill down into the Uninstall key using the OpenSubKey Method

      $regkey=$reg.OpenSubKey($UninstallKey)

      #Retrieve an array of string that contain all the subkey names

      $subkeys=$regkey.GetSubKeyNames()

      #Open each Subkey and use GetValue Method to return the required values for each

      foreach($key in $subkeys){

          $thisKey=$UninstallKey+”\\”+$key

          $thisSubKey=$reg.OpenSubKey($thisKey)

          $obj = New-Object PSObject

          $obj | Add-Member -MemberType NoteProperty -Name “ComputerName” -Value $pc

          $obj | Add-Member -MemberType NoteProperty -Name “DisplayName” -Value $($thisSubKey.GetValue(“DisplayName”))

          $obj | Add-Member -MemberType NoteProperty -Name “DisplayVersion” -Value $($thisSubKey.GetValue(“DisplayVersion”))

          $obj | Add-Member -MemberType NoteProperty -Name “InstallLocation” -Value $($thisSubKey.GetValue(“InstallLocation”))

          $obj | Add-Member -MemberType NoteProperty -Name “Publisher” -Value $($thisSubKey.GetValue(“Publisher”))

          $obj | Add-Member -MemberType NoteProperty -Name "InstanceId" -Value $($thisSubKey.GetValue("InstanceId"))

          $array += $obj

      }

  }
}
End{
  if($Export){
    Write-Verbose "Exporting to CSV..."
    $array | Where-Object { $_.DisplayName } | select ComputerName, DisplayName, DisplayVersion, Publisher, InstanceId | export-csv -path "$path\$filename"
  }
  if($Display){
    $array | Where-Object { $_.DisplayName } | select ComputerName, DisplayName, DisplayVersion, Publisher, InstanceId
  }
}

Export-ModuleMember -Function Get-Software
