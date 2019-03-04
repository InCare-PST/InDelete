﻿function Get-DomainAVStatus{
<#
#>
    [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
    $ClientName = [Microsoft.VisualBasic.Interaction]::InputBox("Enter a Client Name", "Client Name", "")
    $OnlineComputers = @()
    Import-Module ActiveDirectory
    $date = (get-date).AddDays(-60)
    $computers = Get-ADComputer -Filter * -Properties LastLogonDate,OperatingSystem | where lastlogondate -GE $date
    $TotalServers = $computers | where operatingsystem -Match server    
    $TotalWorkstations = $computers | where operatingsystem -NotMatch server
    $pool = [RunspaceFactory]::CreateRunspacePool(1, [int]$env:NUMBER_OF_PROCESSORS + 100)
    $pool.ApartmentState = "MTA"
    $pool.Open()
    $runspaces = @()
    $scriptblock1 ={
        param(
            $comp,
            $OperatingSystem
        )
            if (Test-Connection -ComputerName $comp -Count 1 -Quiet) {
                $temparray = @{
                    name = $comp
                    OperatingSystem = $OperatingSystem
                }
                $online = New-Object -TypeName psobject -Property $temparray
                #$OnlineComputers += $comp
            }
            $online                    
        }
    $workstations = $OnlineComputers | where operatingsystem -NotMatch server
    $servers = $OnlineComputers | where operatingsystem -Match server
    $ComputerSummary = @{
        "Total Servers" = $TotalServers.count
        "OnLine Servers" = $servers.count
        "Total Workstations" = $TotalWorkstations.count
        "OnLine Workstations" = $workstations.count
    }
    $AgentTotal = New-Object -TypeName psobject -Property $ComputerSummary
    $errorcomps = @()
    $AVStatusList = foreach ($computer in $workstations){
        $CompAVs = try {
                        Get-WmiObject -ComputerName $computer.name -Namespace root\securitycenter2 -Class AntivirusProduct -ErrorAction SilentlyContinue
                        #Get-CimInstance -ComputerName $computer.name -Namespace root\securitycenter2 -Class AntivirusProduct #-ErrorAction SilentlyContinue
                    }
                    catch{
                        $computer.name
                        $errorcomps += $computer
                        #Write-Host "Cannot connect to $($computer.name)"
                    }
        $ComputerAVList = foreach ($avfound in $CompAVs){
            switch ($avfound.productstate){
                "262144" {$UpdateStatus = "Up to date" ;$RealTimeProtectionStatus = "Disabled"} 
                "262160" {$UpdateStatus = "Out of date" ;$RealTimeProtectionStatus = "Disabled"} 
                "266240" {$UpdateStatus = "Up to date" ;$RealTimeProtectionStatus = "Enabled"} 
                "266256" {$UpdateStatus = "Out of date" ;$RealTimeProtectionStatus = "Enabled"} 
                "393216" {$UpdateStatus = "Up to date" ;$RealTimeProtectionStatus = "Disabled"} 
                "393232" {$UpdateStatus = "Out of date" ;$RealTimeProtectionStatus = "Disabled"} 
                "393488" {$UpdateStatus = "Out of date" ;$RealTimeProtectionStatus = "Disabled"} 
                "397312" {$UpdateStatus = "Up to date" ;$RealTimeProtectionStatus = "Enabled"} 
                "397328" {$UpdateStatus = "Out of date" ;$RealTimeProtectionStatus = "Enabled"} 
                "397584" {$UpdateStatus = "Out of date" ;$RealTimeProtectionStatus = "Enabled"} 
                "397568" {$UpdateStatus = "Up to date"; $RealTimeProtectionStatus = "Enabled"}
                "393472" {$UpdateStatus = "Up to date" ;$RealTimeProtectionStatus = "Disabled"}
                default {$UpdateStatus = "Unknown" ;$RealTimeProtectionStatus = "Unknown"} 
            }
            $Temphash = @{
                ComputerName = $computer.name
                OS = $computer.OperatingSystem
                AntiVirus = $avfound.displayname
                Status = $RealTimeProtectionStatus
                "Update Status" = $UpdateStatus
            }
            $AVObj = New-Object -TypeName psobject -Property $Temphash
            $AVObj
        }
        $ComputerAVList | select ComputerName,OS,AntiVirus,Status,"Update Status"
    }
    $ServerDriveSpace = @()
    $ServerTotalSpace = @()
    foreach ($server in $servers){
        try{
            $ServerTempSpace = @()
            $vol = Get-CimInstance -ClassName Win32_Volume -ComputerName $server.name -Filter "drivetype=3" -ErrorAction Stop
                foreach ($drive in $vol){
                    if ($drive.driveletter -match "[A-Z]:") {
                        $size = "{0:N2}" -f ($drive.capacity / 1GB)
                        $freespace = "{0:N2}" -f ($drive.freespace / 1GB)
                        $props = @{
                            'ComputerName'=$server.name;
                            'Drive'=$drive.name;
                            'Size(GB)'=$size;
                            'Freespace(GB)'=$freespace;
                            'Used Space(GB)'=[math]::round(($size - $freespace),2) 
                        }
                        $obj = New-Object -TypeName psobject -Property $props
                        $ServerDriveSpace += $obj
                        $ServerTempSpace += $obj
                    }
                }
        }
        catch{
        }
        $totalspace = 0
        foreach ($drive2 in $ServerTempSpace){
            #$drive2.("Used Space")
            $totalspace += $drive2.("Used Space(GB)")
            #$totalspace
        }
        $props2 = @{
            'ComputerName' = $server.name
            'OS' = $server.OperatingSystem
            'Total Used Space(GB)' = $totalspace
        }
        $obj2 = New-Object -TypeName psobject -Property $props2
        $ServerTotalSpace += $obj2
        Clear-Variable totalspace,servertempspace
    }
    $precontent = "<img class='inc-logo' src='https://incaretechnologies.com/wp-content/uploads/InCare_Technologies_horizontal-NEW-NoCross-OUTLINES-for-Web.png'/><H1>$ClientName</H1>"
    $css = "https://incaretechnologies.com/css/incare.css"
    $b += $AgentTotal | select "Total Servers","OnLine Servers","Total Workstations","OnLine Workstations"| ConvertTo-Html -Fragment -PreContent "<h2>InCare Agent Count</h2>" | Out-String
    $b += $ServerTotalSpace | Select ComputerName,OS,"Total Used Space(GB)"| ConvertTo-Html -Fragment -PreContent "<h2>Total Used Space</h2>" | Out-String
    $b += $ServerDriveSpace | select ComputerName,Drive,"Size(GB)","Freespace(GB)","Used Space(GB)" | ConvertTo-Html -Fragment -PreContent "<h2>Server Disks:</h2>" | Out-String
    $b += $AVStatusList | ConvertTo-Html -Fragment -PreContent "<h2>AV Status</h2>" | Out-String
    $HTMLScratch = ConvertTo-Html -Title "InCare Inventory" -Head $precontent -CssUri $css -Body $b -PostContent "<H5><i>$(get-date)</i></H5>"
    #$HTMLScratch | Out-File C:\Users\incare\Desktop\newtest02.html
    $body = $HTMLScratch | Out-String
    $ServerTotalSpace | Export-Csv Servertotalspace.csv -NoTypeInformation
    $ServerDriveSpace | Export-Csv ServerDriveSpace.csv -NoTypeInformation
    $AVStatusList | Export-Csv AVStatusList.csv -NoTypeInformation
    $login = "incaresales"
    $password = "Coffeeis4Clos3rz!@!@" | Convertto-SecureString -AsPlainText -Force
    $credentials = New-Object System.Management.Automation.Pscredential -Argumentlist $login,$password
    $MailMessage = @{ 
        To = "support@incaretechnologies.com"
        From = "incare.analysis@incare360.com" 
        Subject = "InCare Audit for $ClientName" 
        Body = "$body"
        BodyAsHTML = $True
        Smtpserver = "notify.incare360.net"
        Credential = $credentials
        Attachments = ".\Servertotalspace.csv",".\ServerDriveSpace.csv",".\AVStatusList.csv"
    }
    Send-MailMessage @MailMessage
    Remove-Item -Path .\Servertotalspace.csv -Force
    Remove-Item -Path .\ServerDriveSpace.csv -Force
    Remove-Item -Path .\AVStatusList.csv -Force

    $scriptpu = New-Object -ComObject Wscript.Shell
    $scriptpu.popup("Analysis Complete",0,"Press OK",0x1)
}
Get-DomainAVStatus