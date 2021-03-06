﻿Function Get-InactiveUsers {
<#
.SYNOPSIS Function for retrieving,disabling, and moving user accounts that have not been used in a specified amount of time.
.DESCRIPTION Allows an admin to process stale user accounts by finding user accounts that havent been used in a determined amount of time and then either exporting them
            to file, disabling them, moving them, or any combination.
.PARAMETER Time
.PARAMETER Path
.PARAMETER Credentials
.PARAMETER Export
.PARAMETER Disable
.PARAMETER Move
.PARAMETER OU
.EXAMPLE
.EXAMPLE
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

        param(

        [string]$Time=90,

        [string]$Path="C:\temp",

        [string]$Credentials,

        [switch]$Export,

        [switch]$Disable,

        [switch]$IsEnabled,

        [switch]$Move,

        [string]$OU="*"

        )
        begin{
            $Date=get-date
            $Period = ($Date).adddays(-$time)
            $FileName = $Date.tostring("dd-MM-yyyy")+" "+"InactiveUsers.csv"
            $Users = Get-ADUser -Filter {enabled -eq $true}
            if ([bool]$Credentials) {
                $Creds=Get-Credential
            }
            if (!(Test-Path $Path)) {
                Write-Host "Creating Directory $Path"
                New-Item -Path $Path -ItemType Directory
            }
        }
        Process{
            if ([bool]$Credentials) {
                $InactivePresort = Get-ADUser -Credential $Creds -Filter {LastLogonTimeStamp -lt $Period -and enabled -eq $true} -Properties LastLogonTimeStamp
                $Inactive = $InactivePresort | select-object Name,SamAccountName,@{Name="Last Logon Time"; Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp).ToString('yyyy-MM-dd_hh:mm:ss')}} | Sort-Object Name
                if ($Export) {
                    Write-Verbose "Exporting to CSV"
                    $Inactive | Export-Csv -Path "$Path\$FileName" -NoTypeInformation
                    $TotalUsers=Write-Host "Total Enabled Users" $Users.count
                    $TotalInActive=Write-Host "Total Inactive Users" $Inactive.count
                }
                Else {
                    $Inactive | Out-Host
                }
            }
            else {
                $InactivePresort = Get-ADUser -Filter {LastLogonTimeStamp -lt $Period -and enabled -eq $true} -Properties LastLogonTimeStamp
                $Inactive = $InactivePresort | select-object Name,SamAccountName,@{Name="Last Logon Time"; Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp).ToString('yyyy-MM-dd_hh:mm:ss')}} | Sort-Object Name
                if ($Export) {
                    Write-Verbose "Exporting to CSV"
                    $Inactive | Export-Csv "$Path\$FileName" -NoTypeInformation
                }
                Else {
                    $Inactive | Out-host
                }
            }
            if($Move) {
                $ORGU = Get-ADOrganizationalUnit -Filter 'name -like $OU' -Properties Name,DistinguishedName | select Name,Distinguishedname
                if ($ORGU.count -ge 2){
                    $ORG = $ORGU | Out-GridView -Title "Please Choose the Target OU" -OutputMode Single
                }
                else {
                    $ORG = $ORGU
                }
                $InactivePresort | Move-ADObject -TargetPath $ORG.Distinguishedname
            }
            if($Disable) {
                $InactivePresort | Disable-ADAccount

            }
        }
        End{
            Write-Host "Total Enabled Users" $Users.count
            Write-Host "Total Inactive Users" $Inactive.count

        }
}

Function Remove-MalFiles {
<#
Synopsis



#>
    [cmdletbinding(SupportsShouldProcess = $True)]
        param(
            $RunTime = "24",

            [switch]$LogOnly,

            [switch]$RunOnce,

            [string]$LogDir = "C:\Temp",

            [int32]$LastLogon = "60",

            [switch]$UseList
        )
    Begin{
        $RunTimeLoop = (Get-Date).AddHours($RunTime)
        if(!(Test-Path $LogDir)){
            New-Item -Path $LogDir -ItemType Directory
        }
    }
    Process{
        While((Get-date) -le $RunTimeLoop){
            $WRMComp = @()
            $NWRM = @()
            $date = (get-date).AddDays(-$LastLogon)
            if($LogOnly -or $RunOnce){
                $RunTimeLoop = (Get-Date)
            }
            if ($UseList){
                $WRMComp = Import-Clixml -Path $LogDir\WRMComp.xml
                $NWRM = Import-Clixml -Path $LogDir\NOWRM.xml
            }
            else {
                $computers = Get-ADComputer -Filter * -Properties LastLogonDate | Where-Object {$_.lastlogondate -GE $date}
                ForEach ($comp in $computers) {
                    if (Test-Connection -ComputerName $comp.name -Count 1 -Quiet) {
                        Write-Host $comp.name "is Alive"
                        if ([bool](Test-WSMan -ComputerName $comp.Name -ErrorAction SilentlyContinue)){
                            $WRMComp += $comp
                        }
                        else {
                            $NWRM += $comp
                        }
                    }
                    <#$WRMComp | Export-Clixml $LogDir\WRMComp.xml
                    $NWRM | Export-Clixml $LogDir\NOWRM.xml
                    $NWRM | Select-Object Name,DistinguishedName,LastLogonDate | Export-Csv $LogDir\NWRM.csv -Append -NoTypeInformation#>
                }
                $WRMComp | Export-Clixml $LogDir\WRMComp.xml
                $NWRM | Export-Clixml $LogDir\NOWRM.xml
                $NWRM | Select-Object Name,DistinguishedName,LastLogonDate | Export-Csv $LogDir\NWRM.csv -Append -NoTypeInformation
            }
            #$LegacyJob = Start-Job -ScriptBlock {Remove-EmotetLegacy -ComputerName ($NWRM.name) -LogDir $LogDir -Logonly $LogOnly}
            $looptime = (Get-Date).AddMinutes(30)
            while ((Get-Date) -le $looptime){
                if($LogOnly -or $RunOnce){
                    $looptime = (Get-Date)
                }
                $ScanTime = (Get-Date).ToString('yyyy-MM-dd')
                if (Test-Path "$LogDir\exclude32.txt") {
                    $exclude32 = Get-Content -Path $LogDir\exclude32.txt
                }
                if (Test-Path "$LogDir\exclude64.txt") {
                    $exclude64 = Get-Content -Path $LogDir\exclude64.txt
                }
                if (Test-Path "$LogDir\excludewindows.txt") {
                    $excludewin = Get-Content -Path $LogDir\excludewindows.txt
                }
                Invoke-Command -ComputerName $WRMComp.name -ArgumentList $LogOnly,$exclude32,$exclude64,$excludewin{
                    param($LogOnly,$exclude32,$exclude64,$excludewin)
                    $deletedfiles = @()
                    $ComputerName = $env:COMPUTERNAME
                    <#if (Test-Path -Path "C:\windows\SysWOW64") {
                        $file = Get-ChildItem -Path "C:\windows\syswow64" *.exe | where {$_.creationtime -ge (get-date).AddDays(-1.5) -and $_.name -ne $_.originalname -and $_.name -notmatch $exclude64}
                            foreach ($bfile in $file){
                                if ([bool]$bfile){
                                    $filedeleted = $false
                                    $filepath = $bfile.fullname
                                    if (!($LogOnly)){
                                        try {
                                            Stop-Process -Name $bfile.basename -Force -ErrorAction SilentlyContinue
                                        }
                                        catch{

                                        }
                                        #Start-Sleep -Seconds 3
                                        try {
                                            Remove-Item $bfile.fullname -ErrorAction Stop
                                            $filedeleted = $true
                                        }
                                        catch{
                                            $filedeleted = $false
                                        }
                                    }
                                    if ($filedeleted){
                                        $delstatus = "Yes"
                                        write-host "$filepath was detected on $ComputerName and was deleted" -ForegroundColor Red
                                    }
                                    else {
                                        $delstatus = "No"
                                        write-host "$filepath was detected on $ComputerName but was not deleted" -ForegroundColor Red
                                    }
                                    $tempobj = @{
                                        Name = $bfile.name
                                        Directory = $bfile.FullName
                                        CreationDate = $bfile.creationtime
                                        Deleted = $delstatus
                                        Command = $Task
                                        Type = "Dropper"
                                        ComputerName = $ComputerName
                                        TimeStamp = (Get-Date -Format "dd-MM-yyyy HH:mm:ss")
                                    }
                                    $FileObj = New-Object -TypeName psobject -Property $tempobj
                                    $deletedfiles += $FileObj
                                }else{
                                write-host "$ComputerName 64 Bit System Did not detect Dropper" -ForegroundColor Green
                                }
                        }
                    }
                    if (!(Test-Path -Path "C:\windows\SysWOW64")) {
                        $file = Get-ChildItem -Path "C:\windows\system32" *.exe | where {$_.creationtime -ge (get-date).AddDays(-1.5) -and $_.name -ne $_.originalname -and $_.name -notmatch $exclude32}
                            foreach ($bfile in $file){
                                if ([bool]$bfile){
                                    $filedeleted = $false
                                    $filepath = $bfile.fullname
                                    if (!($LogOnly)){
                                        try {
                                            Stop-Process -Name $bfile.basename -Force -ErrorAction SilentlyContinue
                                        }
                                        catch{

                                        }
                                    }
                                        #Start-Sleep -Seconds 3
                                        try {
                                            Remove-Item $bfile.fullname -ErrorAction Stop
                                            $filedeleted = $true
                                        }
                                        catch{
                                            $filedeleted = $false
                                        }
                                    if ($filedeleted){
                                        $delstatus = "Yes"
                                        write-host "$filepath was detected on $ComputerName and was deleted" -ForegroundColor Red
                                    }
                                    else {
                                        $delstatus = "No"
                                        write-host "$filepath was detected on $ComputerName but was not deleted" -ForegroundColor Red
                                    }
                                    $tempobj = @{
                                        Name = $bfile.name
                                        Directory = $bfile.FullName
                                        CreationDate = $bfile.creationtime
                                        Deleted = $delstatus
                                        Command = $Task
                                        Type = "Dropper"
                                        ComputerName = $ComputerName
                                        TimeStamp = (Get-Date -Format "dd-MM-yyyy HH:mm:ss")
                                    }
                                    $FileObj = New-Object -TypeName psobject -Property $tempobj
                                    $deletedfiles += $FileObj
                                }else{
                                write-host "$ComputerName 32 Bit System Did not detect Dropper" -ForegroundColor Green
                                }
                        }
                    }
                    $file = get-childitem -Path "C:\Windows" *.exe | where {$_.creationtime -ge (get-date).AddDays(-1.5) -and $_.Name -match "(?i)(\w{8}\.exe)" -and $_.name -notmatch $excludewin}
                            foreach ($bfile in $file){
                                if ([bool]$bfile){
                                    $filedeleted = $false
                                    $filepath = $bfile.fullname
                                    if (!($LogOnly)){
                                        try {
                                            Stop-Process -Name $bfile.basename -Force -ErrorAction SilentlyContinue
                                        }
                                        catch{

                                        }
                                        #Start-Sleep -Seconds 3
                                        try {
                                            Remove-Item $bfile.fullname -ErrorAction Stop
                                            $filedeleted = $true
                                        }
                                        catch{
                                            $filedeleted = $false
                                        }
                                    }
                                    if ($filedeleted){
                                        $delstatus = "Yes"
                                        write-host "$filepath was detected on $ComputerName and was deleted" -ForegroundColor Red
                                    }
                                    else {
                                        $delstatus = "No"
                                        write-host "$filepath was detected on $ComputerName but was not deleted" -ForegroundColor Red
                                    }
                                    $tempobj = @{
                                        Name = $bfile.name
                                        Directory = $bfile.FullName
                                        CreationDate = $bfile.creationtime
                                        Deleted = $delstatus
                                        Command = $Task
                                        Type = "Emotet"
                                        ComputerName = $ComputerName
                                        TimeStamp = (Get-Date -Format "dd-MM-yyyy HH:mm:ss")
                                    }
                                    $FileObj = New-Object -TypeName psobject -Property $tempobj
                                    $deletedfiles += $FileObj
                                    #$deletedfiles += ($bfile | select name,directory,creationtime)
                                }else{
                                write-host "$ComputerName Windows Directory does not have any emotet files" -ForegroundColor Green
                                }
                            }
                    $file = get-childitem -path C:\Users\,c:\windows\  * -Recurse -Force -ErrorAction SilentlyContinue | where {$_.name -match "^44\w{62}\.exe$|^m\w\wvca\.exe$|^tetup\.exe|^wbM\w+\.exe|^AIMY"}
                            foreach ($bfile in $file){
                                if ([bool]$bfile){
                                    $filedeleted = $false
                                    $filepath = $bfile.fullname
                                    if (!($LogOnly)){
                                        try {
                                            Stop-Process -Name $bfile.basename -Force -ErrorAction SilentlyContinue
                                        }
                                        catch{

                                        }
                                        #Start-Sleep -Seconds 3
                                        try {
                                            Remove-Item $bfile.fullname -Recurse -ErrorAction Stop
                                            $filedeleted = $true
                                        }
                                        catch{
                                            $filedeleted = $false
                                        }
                                    }
                                    if ($filedeleted){
                                        $delstatus = "Yes"
                                        write-host "$filepath was detected on $ComputerName and was deleted" -ForegroundColor Red
                                    }
                                    else {
                                        $delstatus = "No"
                                        write-host "$filepath was detected on $ComputerName but was not deleted" -ForegroundColor Red
                                    }
                                    $tempobj = @{
                                        Name = $bfile.name
                                        Directory = $bfile.FullName
                                        CreationDate = $bfile.creationtime
                                        Deleted = $delstatus
                                        Command = $Task
                                        Type = "44Trojan"
                                        ComputerName = $ComputerName
                                        TimeStamp = (Get-Date -Format "dd-MM-yyyy HH:mm:ss")
                                    }
                                    $FileObj = New-Object -TypeName psobject -Property $tempobj
                                    $deletedfiles += $FileObj
                                    #$deletedfiles += ($bfile | select name,directory,creationtime)
                                }else{
                                write-host "$ComputerName C:\Users and C:\Windows does not have 44Trojan files" -ForegroundColor Green
                                }
                            }#>
                    $file = get-childitem -path C:\programdata *.dll -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {$_.name -match "\w{8}-(\w{4}-){3}\w{12}\.dll"}
                            foreach ($bfile in $file){
                                if ([bool]$bfile){
                                    $filedeleted = $false
                                    $filepath = $bfile.fullname
                                    if (!($LogOnly)){
                                        try {
                                            Stop-Process -Name $bfile.basename -Force -ErrorAction SilentlyContinue
                                        }
                                        catch{

                                        }
                                        #Start-Sleep -Seconds 3
                                        try {
                                            Remove-Item $bfile.fullname -ErrorAction Stop
                                            $filedeleted = $true
                                        }
                                        catch{
                                            $filedeleted = $false
                                        }
                                    }
                                    if ($filedeleted){
                                        $delstatus = "Yes"
                                        write-host "$filepath was detected on $ComputerName and was deleted" -ForegroundColor Red
                                    }
                                    else {
                                        $delstatus = "No"
                                        write-host "$filepath was detected on $ComputerName but was not deleted" -ForegroundColor Red
                                    }
                                    $tempobj = @{
                                        Name = $bfile.name
                                        Directory = $bfile.FullName
                                        CreationDate = $bfile.creationtime
                                        Deleted = $delstatus
                                        Command = $Task
                                        Type = "44Trojan"
                                        ComputerName = $ComputerName
                                        TimeStamp = (Get-Date -Format "dd-MM-yyyy HH:mm:ss")
                                    }
                                    $FileObj = New-Object -TypeName psobject -Property $tempobj
                                    $deletedfiles += $FileObj
                                    #$deletedfiles += ($bfile | select name,directory,creationtime)
                                }else{
                                write-host "$ComputerName C:\ Directory does not have 44Trojan files" -ForegroundColor Green
                                }
                            }
                    <#$file = get-childitem -path C:\Windows\System32\Tasks  * | where {$_.name -match "Msne?tcs"}
                            foreach ($bfile in $file){
                                if ([bool]$bfile){
                                    $filedeleted = $false
                                    $filepath = $bfile.fullname
                                    [xml]$xmltemp = get-content $filepath
                                    $Task = $xmltemp.task.actions.exec.command
                                    if (!($LogOnly)){
                                        <#try {
                                            Stop-Process -Name $bfile.basename -Force -ErrorAction SilentlyContinue
                                        }
                                        catch{

                                        }#>
                                        #Start-Sleep -Seconds 3
                                        <#try {
                                            Remove-Item $bfile.fullname -ErrorAction Stop
                                            $filedeleted = $true
                                        }
                                        catch{
                                            $filedeleted = $false
                                        }
                                    }
                                    if ($filedeleted){
                                        $delstatus = "Yes"
                                        write-host "$filepath was detected on $ComputerName and was deleted" -ForegroundColor Red
                                    }
                                    else {
                                        $delstatus = "No"
                                        write-host "$filepath was detected on $ComputerName but was not deleted" -ForegroundColor Red
                                    }
                                    $tempobj = @{
                                        Name = $bfile.name
                                        Directory = $bfile.FullName
                                        CreationDate = $bfile.creationtime
                                        Deleted = $delstatus
                                        Command = $Task
                                        Type = "TrickBot Task"
                                        ComputerName = $ComputerName
                                        TimeStamp = (Get-Date -Format "dd-MM-yyyy HH:mm:ss")
                                    }
                                    $FileObj = New-Object -TypeName psobject -Property $tempobj
                                    $deletedfiles += $FileObj
                                    #$deletedfiles += ($bfile | select name,directory,creationtime)
                                }else{
                                write-host "$ComputerName C:\windows\system32\tasks Directory does not have trickbot files" -ForegroundColor Green
                                }
                            }#>


                $deletedfiles
                } | Select-Object Name,Directory,CreationDate,Deleted,Command,Type,ComputerName,TimeStamp | Export-Csv -Path $LogDir\Deleted-Emotet-Files.csv -Append -Force -NoTypeInformation
            Start-Sleep -Seconds 30
            }
        }
    }
    End{
        $FTimeStamp = (Get-Date -Format "dd-MM-yyyy HH-mm-ss")
        Rename-Item -Path $LogDir\Deleted-Emotet-Files.csv -NewName Deleted-Emotet-Files-RuntimeEnded-$FTimeStamp.csv
    }

}

Function Get-OnlineADComps {
<#
Synopsis

#>

    [cmdletbinding()]
        param(

            $RunTime = 24,

            [string]$LogDir = "c:\temp",

            [int32]$LastLogon = 60,

            [switch]$LogOnly,

            [switch]$RunOnce

        )
    Begin{
        $RunTimeLoop = (Get-Date).AddHours($RunTime)
        $pool = [RunspaceFactory]::CreateRunspacePool(1, [int]$env:NUMBER_OF_PROCESSORS + 100)
        $pool.ApartmentState = "MTA"
        $pool.Open()
        $runspaces = @()
        $scriptblock = {
            Param(
                $Comp,
                $DistinguishedName,
                $LastLogonDate,
                $OperatingSystem
            )
            if (Test-Connection -ComputerName $comp -Count 1 -Quiet) {
                $Alive = "Yes"
                if ([bool](Test-WSMan -ComputerName $comp -ErrorAction SilentlyContinue)){
                    $WSMAN = "Enabled"
                }
                else {
                    $WSMAN = "Disabled"
                }
                $tempobj = @{
                    Name = $Comp
                    DistinguishedName = $DistinguishedName
                    LastLogonDate = $LastLogonDate
                    PsRemoting = $WSMAN
                    OperatingSystem = $OperatingSystem
                }
                $obj = New-Object -TypeName psobject -Property $tempobj
                $obj | select Name,LastLogonDate,PsRemoting,OperatingSystem,DistinguishedName
            }
        }
    }
    Process{
        While((Get-date) -le $RunTimeLoop){
            #$WRMComp = @()
            #$NWRM = @()
            $starttime=(get-date)
            $date = (get-date).AddDays(-$LastLogon)
            if($LogOnly -or $RunOnce){
                $RunTimeLoop = (Get-Date)
            }
            $computers = Get-ADComputer -Filter * -Properties LastLogonDate,OperatingSystem | Where-Object {$_.lastlogondate -GE $date}
            foreach($comp in $computers) {
                $paramlist = @{
                    Comp = $comp.name
                    DistinguishedName = $comp.DistinguishedName
                    LastLogonDate = $comp.LastLogonDate
                    OperatingSystem = $comp.OperatingSystem
                }
                $runspace = [PowerShell]::Create()
                $null = $runspace.AddScript($scriptblock)
                $null = $runspace.AddParameters($paramlist)
                $runspace.RunspacePool = $pool
                $runspaces += [PSCustomObject]@{ Pipe = $runspace; Status = $runspace.BeginInvoke() }
            }

            $onlinecomps = while ($runspaces.Status -ne $null){
                $completed = $runspaces | Where-Object { $_.Status.IsCompleted -eq $true }
                foreach ($runspace in $completed)
                {
                    $runspace.Pipe.EndInvoke($runspace.Status)
                    $runspace.Status = $null
                }
            }
            $PsRemotingEnabled = $onlinecomps | Where-Object {$_.PsRemoting -eq "Enabled"}
            $PsRemotingDisabled = $onlinecomps | Where-Object {$_.PsRemoting -eq "Disabled"}
            Write-Output "$($onlinecomps.count) have been detected online"
            Write-Output "$($PsRemotingEnabled.count) are responding via PSRemote"
            Write-Output "$($PsRemotingDisabled.count) need to have PSRemoting enabled or addressed"
            $PsRemotingEnabled | Export-Clixml $LogDir\WRMComp.xml
            $PsRemotingDisabled | Export-Clixml $LogDir\NOWRM.xml
            $FTimeStamp = (Get-Date -Format "dd-MM-yyyy HH-mm-ss")
            $PsRemotingDisabled | Select-Object Name,LastLogonDate,OperatingSystem,DistinguishedName | Export-Csv $LogDir\NoPSRemoting_$FTimeStamp.csv -Append -NoTypeInformation
            $endtime=(get-date)
            if(($endtime - $starttime).seconds -le 300 -and !($RunOnce)){
                Start-Sleep -Seconds (300 - ($endtime - $starttime).seconds)
            }
        }
    }
    End{
        $pool.Close()
        $pool.Dispose()
    }
}

function Add-DHCPv4Reservation {
<#
#>
    [cmdletbinding()]
        param(
        [parameter(Mandatory=$true)]
        [string]$CSVPath,

        [parameter(Mandatory=$true)]
        [string]$ScopeID

        )
    Begin{
        $list = Import-Csv $CSVPath
    }
    Process{
        foreach($item in $list){
            Add-DhcpServerv4Reservation -ScopeId $ScopeID -IPAddress $item.ipaddress  -Name $item.name -Description $item.description -ClientId $item.clientid
        }
    }
    End{
    }
}

function Get-LTServerAdd {
<#
.SYNOPSIS
This command is for checking online domain computers for the proper labtech reporting server setting and returning that information.
.DESCRIPTION
Checks a registry key in the labtech hive to see if the server has been properly configured for the Labtech agent. It reports back
on the setting and if labtech was actually installed. It can also be set to email reports
.PARAMETER LogDir
This parameter sets the working dirctory for the command. The default is C:\temp
.PARAMETER ServerAddr
This parameter specifies the correct server address for the Labtech reporting server. Currently set to "https://cwa.incare360.com" by default
.PARAMETER Exclude
Specifies if certain computers should be excluded from the scan. The options are Servers, Workstations, or a list in a csv file called exclude.csv. The file should
have only one column called name
.PARAMETER Report
This specifies if the command should send a report through email. It only emails a report if there are machines misconfigured or without the InCare agent.
If this Parameter is selected then a set of credentials needs to be saved in the working directory using the Protect-creds command.
.PARAMETER Email
Specifies the email address the report should be sent to.
.PARAMETER ClientName
Specifies the name of the client the report is being run from.
.Example
Get-LTServerAdd 
This will check all currently online domain computers for the correct server setting and export the results to C:\Temp
.Example 
Get-LTServerAdd -Logdir C:\AgentCheck -Exclude Servers
This will check all currently online domain workstations and not the servers. The results will be exported to C:\AgentCheck
.Example
GEt-LTServerAdd -Report -Email someone@InCare360.com -ClientName "USA HealthCare"
Check all online computers in the domain, if any do not have the correct server setting, or have labtech installed a report will be emailed to "someone@incare360.com"
.Example
powershell.exe -noexit -command  &{Get-LTServerAdd -LogDir C:\Users\incare\Documents\LTAgent -report -email someone@incare360.com -ClientName "A Client"}; exit
Using this format the command can be added to the windows task scheduler. Make sure it is set to run during regular business hours when the most Computers will be online.
#>
    [cmdletbinding(DefaultParameterSetName="Default")]
        param(
            [Parameter(ParameterSetName="Default")]
            [Parameter(ParameterSetName="Reporting",Mandatory=$false)]
            [string]$LogDir = "c:\temp",

            [Parameter(ParameterSetName="Default")]
            [Parameter(ParameterSetName="Reporting",Mandatory=$false)]
            [string]$ServerAddr = "https://cwa.incare360.com",

            [Parameter(ParameterSetName="Default")]
            [Parameter(ParameterSetName="Reporting",Mandatory=$false)]
            [ValidateSet("Servers", "Workstations", "List")]
            [string]$Exclude,

            [Parameter(ParameterSetName="Reporting",Mandatory=$false)]
            [switch]$report,

            [Parameter(ParameterSetName="Reporting",Mandatory=$true)]
            [string]$email,

            [Parameter(ParameterSetName="Reporting",Mandatory=$true)]
            [string]$ClientName

        )
    Begin{
        $CurrentFullLTVersion = (Get-ItemProperty -Path HKLM:\software\LabTech\Service\).'Version'
        $CurrentLTVersion = ([regex]::Match($CurrentFullLTVersion, '.*(?=\.)')).value
        if($report){
            $credentials = Import-Clixml -path "$logdir\incare.xml"
        }
        if(!(Test-Path $LogDir)){
            New-Item -Path $LogDir -ItemType Directory
        }
        Start-Job -Name Verify -ArgumentList $Logdir{
            Param($Logdir)
                Get-OnlineADComps -RunOnce -LogDir $LogDir
            }
        $waiting = $true
        while($waiting){
            $VerifyJob = Get-Job -Name Verify
            if ($VerifyJob.state -ne "Running" -and $VerifyJob.state -ne "Completed"){
                Write-Host "Could not complete computer query"
                Receive-Job -Name Verify
                $waiting = $false
            }
            if ($VerifyJob.State -eq "Completed"){
                $WRMComp = Import-Clixml -Path $LogDir\WRMComp.xml
                #$ComputerName = $WRMComp.name
                Receive-Job -Name Verify
                $waiting = $false
            }
        }
        switch ($Exclude){
            "Servers" {$ComputerName = ($WRMComp | Where-Object {$_.operatingsystem -notmatch "server"}).name}
            "Workstations" {$ComputerName = ($WRMComp | Where-Object {$_.operatingsystem -match "server"}).name}
            "List" {$ComputerName = $WRMComp.name;$Excludes = Import-Csv $LogDir\exclude.csv;foreach ($ex in $Excludes.name){$ComputerName = $ComputerName | Where-Object {$_ -notmatch $ex}} }
            default {$ComputerName = $WRMComp.name}
        }
    }
    Process{
        $agentlist = Invoke-Command -ComputerName $ComputerName{
            $serveraddress = (Get-ItemProperty -Path HKLM:\software\LabTech\Service\).'server address'
            $ltversion = (Get-ItemProperty -Path HKLM:\software\LabTech\Service\).'Version'
            If ([bool]$serveraddress) {
                $tempobj = @{
                    Computername = $env:COMPUTERNAME
                    ServerAddress = $serveraddress
                    LTVersion = $ltversion
                }
            }
            else{
                $installcheck = Get-WmiObject -Class Win32_Product | Where-Object {$_.name -match "labtech"}
                if ([bool]$installcheck){
                    $installstate = "Server Address not found"
                }
                else{
                    $installstate = "Labtech Agent not installed"
                }
                $tempobj = @{
                    Computername = $env:COMPUTERNAME
                    ServerAddress = $installstate
                    LTVersion = "NA"
                }
            }
            $ExportObj = New-Object -TypeName psobject -Property $tempobj
            $ExportObj

        } | Select-Object Computername,ServerAddress,LTVersion #|Export-Csv -Path $LogDir\Get_LTAddr_Log.csv -Append -Force -NoTypeInformation
        if ($report){
            $agentissues = $agentlist | Where-Object {$_.serveraddress -ne $ServerAddr -or ([regex]::Match($_.LTVersion,'.*(?=\.)')).value -ne $CurrentLTVersion}
            if ([bool]$agentissues){
                $agentissues | Export-Csv -Path $LogDir\Get_LTAddr_Log.csv -Append -Force -NoTypeInformation
                $b = $agentissues | ConvertTo-Html -Fragment -PreContent "<h2>LTAgent Issues:</h2>" | Out-String
                $css = "https://incaretechnologies.com/css/incare.css"
                $precontent = "<img class='inc-logo' src='https://incaretechnologies.com/wp-content/uploads/InCare_Technologies_horizontal-NEW-NoCross-OUTLINES-for-Web.png'/><H1>$ClientName</H1>"
                $HTMLScratch = ConvertTo-Html -Title "InCare Agent Issues" -Head $precontent -CssUri $css -Body $b -PostContent "<H5><i>$(get-date)</i></H5>"
                $Body = $HTMLScratch | Out-String
                $MailMessage = @{
                    To = "$email"
                    From = "incare.analysis@incare360.com"
                    Subject = "InCare Agent Report From $ClientName"
                    Body = "$body"
                    BodyAsHTML = $True
                    Smtpserver = "notify.incare360.net"
                    Credential = $credentials
                    Attachments = "$LogDir\Get_LTAddr_Log.csv"
                }
                Send-MailMessage @MailMessage
            }
        }
        else{
            $agentlist | Export-Csv -Path $LogDir\Get_LTAddr_Log.csv -Append -Force -NoTypeInformation
        }
    }
    End{
        #($NWRM.name).tostring | Export-Csv -Path $LogDir\NoPSComps.csv -NoTypeInformation
        Remove-Item -Path $LogDir\WRMComp.xml
        Remove-Item -Path $LogDir\NOWRM.xml
        Remove-Job -Name Verify -ErrorAction SilentlyContinue
        if ($report){
            Remove-Item -Path $LogDir\Get_LTAddr_Log.csv -ErrorAction SilentlyContinue
            Get-ChildItem $logdir\nopsremoting* | Where-Object {$_.creationtime -le ((get-date).AddDays(-7))} | remove-item
        }
        else{
            $FTimeStamp = (Get-Date -Format "dd-MM-yyyy HH-mm-ss")
            Rename-Item -Path $LogDir\Get_LTAddr_Log.csv -NewName Get_LTAddr_Log_$FTimeStamp.csv
        }

    }
}

function Set-LTServerAdd {
<#
synopsis
#>

    [cmdletbinding()]
        param(

            [Parameter(Position = 0,
            ValueFromPipelineByPropertyName = $true)]
            [string[]]$ComputerName,

            [string]$Logdir = "C:\temp",

            [string]$ServerAddr = "https://cwa.incare360.com"
        )
    Begin{
        if (![bool]$ComputerName) {
            $JobRan = $true
            Start-Job -Name Verify -ArgumentList $Logdir{
                Param($Logdir)
                    Get-OnlineADComps -RunOnce -LogDir $LogDir
            }
            $waiting = $true
            While($waiting){
                $VerifyJob = Get-Job -Name Verify
                if ($VerifyJob.state -ne "Running" -and $VerifyJob.State -ne "Completed"){
                    Write-Host "Could not complete computer query"
                    Receive-Job -Name Verify
                    $waiting=$false
                }
                if($VerifyJob.State -eq "Completed"){
                    $WRMComp = Import-Clixml -Path $LogDir\WRMComp.xml
                    $ComputerName = $WRMComp.Name
                    Receive-Job -Name Verify
                    $waiting = $false
                }
                else{
                    Start-Sleep -Seconds 5
                }
            }
        }
    }
    Process{
        #Try {
            Invoke-Command -ComputerName $ComputerName -ArgumentList $ServerAddr{
                param($ServerAddr)
                try {
                    $currentaddress = (Get-ItemProperty -Path HKLM:\software\LabTech\Service\).'server address'
                }
                catch{
                }
                $Targetname = $env:COMPUTERNAME
                If ([bool]$currentaddress) {
                    $InitialRegEntry = $currentaddress
                    if ($currentaddress -ne $ServerAddr){
                        try {
                            $keychanged = "Yes"
                            #Stop-Service LTSvcMon,LTService -ErrorAction SilentlyContinue
                            Stop-Process -Name LTSVC,LTSvcMon,LTTray -Force -ErrorAction SilentlyContinue
                            Set-ItemProperty -Path HKLM:\software\LabTech\Service\ -Name "server address" -Value $ServerAddr -ErrorAction SilentlyContinue
                            Start-Service LTSvcMon,LTService -ErrorAction SilentlyContinue
                        }
                        catch{
                            $keychanged = "Error"
                        }
                    }
                    else{
                        $keychanged = "Already Correct"
                    }
                }
                else{
                $InitialRegEntry = "Server Address not found"
                }
                $tempobj = @{
                    "ComputerName" = $Targetname
                    "Initial Registry Entry" = $InitialRegEntry
                    "Key Changed" = $keychanged
                }
                $RegObj = New-Object -TypeName psobject -Property $tempobj
                $RegObj
            } | Select-Object "ComputerName","Initial Registry Entry","Key Changed" | Export-Csv -Path $LogDir\Set_LTAddr_Log.csv -Append -Force -NoTypeInformation
        #}
        <#Catch{
            Write-Host "Could not connect to $ComputerName"
        }#>
    }
    End{
        $FTimeStamp = (Get-Date -Format "dd-MM-yyyy HH-mm-ss")
        if($JobRan){
            Remove-Job -Name Verify
            Remove-Item -Path $LogDir\WRMComp.xml
            Remove-Item -Path $LogDir\NOWRM.xml
        }
        Rename-Item -Path $LogDir\Set_LTAddr_Log.csv -NewName Set_LTAddr_Log_$FTimeStamp.csv
    }
}

function Protect-Creds {
<# Synopsis
#>
    [cmdletbinding()]
        param(

            [parameter(mandatory=$true)]
            [string]$logdir

        )
        $credentials = Get-Credential
        $credentials | Export-Clixml "$logdir\incare.xml"
        #$credentials.password | ConvertFrom-SecureString | set-content "$logdir\incarep.txt"
        #$credentials.username | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Set-Content "$logdir\incareu.txt"
}

Function Update-ICTools {
    [cmdletbinding()]
    param(
        [switch]$NoRestart,
        [switch]$Beta
      )


Begin{

if($Beta){
  #Beta Variables
    $url = "https://raw.githubusercontent.com/InCare-PST/ICTools/master/Modules/ICTools/ICTools-Beta.psm1"
          }else{
  #Production Variables
    $url = "https://raw.githubusercontent.com/InCare-PST/ICTools/master/Modules/ICTools/ICTools.psm1"

          }

  #Constant Variables
    $ictpath = "$Home\Documents\WindowsPowerShell\Modules\ICTools"
    $file = "$ictpath\ICTools.psm1"
    $bakfile = "$ictpath\ICtools.bak"
    $temp = "$ictpath\ICTools.temp.psm1"
    $webclient = New-Object System.Net.WebClient
    $psptest = Test-Path $Profile
    $psp = New-Item –Path $Profile –Type File –Force
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
start-sleep -seconds 2


if($NoRestart){
Import-Module ICTools
Remove-Module ICTools
Import-Module ICTools
}
else{
start-process PowerShell
stop-process -Id $PID
}

}

#End of Function
}

Function Import-ICTHistory {
<# This is to Install PSExec #>
    $ictpath = "$Home\Documents\WindowsPowerShell\Modules\ICTools"

if(Test-Path -Path $ictpath\history.csv){
  Import-Csv $ictpath\history.csv | Add-History
}else{
  Write-Host "No History to Import"
}
#End of Function
}

Function Install-PSExec {
<# This is to Install PSExec #>
    $url = "https://live.sysinternals.com/psexec.exe"
    $syspath = "$env:windir\System32\psexec.exe"



if(!(test-path -Path $syspath)){

  [Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls11, Tls, Ssl3"
  $webclient = New-Object System.Net.WebClient
  $webclient.downloadfile($url, $syspath)

}
#End of Function
}

Function Set-FixCellular {
<# This is to correct the Windows 10 when Cellular is diconnected when ethernet plugged in #>

$regpath = HKLM:\SOFTWARE\Microsoft\WcmSvc
$regkey = IgnoreNonRoutableEthernet

if(!(test-path $regpath)){
  New-Item -Path $regpath -Force | Out-Null
  New-ItemProperty -Path $regpath -Name $regkey -Value "1" -PropertyType DWORD -Force | Out-Null
}else{
  New-ItemProperty -Path $regpath -Name $regkey -Value "1" -PropertyType DWORD -Force | Out-Null
}

#End function
}

Export-ModuleMember -Function Set-LTServerAdd,Get-InactiveUsers,Remove-MalFiles,Get-OnlineADComps,Add-DHCPv4Reservation,Get-LTServerAdd,Protect-Creds,Update-ICTools,Install-PSExec,Import-ICTHistory,Set-FixCellular
