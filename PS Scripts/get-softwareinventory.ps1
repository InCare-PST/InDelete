function Get-ICAnalysis{
<#
.Synopsis
#>
    [cmdletbinding()]
        param(
            $Email = "support@incaretechnologies.com"
        )
    begin{
        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
        $ClientName = [Microsoft.VisualBasic.Interaction]::InputBox("Enter a Client Name", "Client Name", "")
        $OnlineComputers = @()
        Import-Module ActiveDirectory
        $date = (get-date).AddDays(-60)
        $pool = [RunspaceFactory]::CreateRunspacePool(1, [int]$env:NUMBER_OF_PROCESSORS + 100)
        $pool.ApartmentState = "MTA"
        $pool.Open()
        $runspaces = @()
        $scriptblock1 = {
            param(
                $compname,
                $OperatingSystem
            )
                if (Test-Connection -ComputerName $compname -Count 1 -Quiet) {
                    $temparray = @{
                        name = $compname
                        OperatingSystem = $OperatingSystem
                    }
                    $online = New-Object -TypeName psobject -Property $temparray
                    $online
                }
                Clear-Variable online
            }
        $scriptblock2 = {
            param(
                $compname,

                $OperatingSystem
            )
            $CompAVs = try {
                            Get-WmiObject -ComputerName $compname -Namespace root\securitycenter2 -Class AntivirusProduct -ErrorAction SilentlyContinue
                        }
                        catch{
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
                    ComputerName = $compname
                    OS = $OperatingSystem
                    AntiVirus = $avfound.displayname
                    Status = $RealTimeProtectionStatus
                    "Update Status" = $UpdateStatus
                }
                $AVObj = New-Object -TypeName psobject -Property $Temphash
                $AVObj
            }
            $ComputerAVList | select ComputerName,OS,AntiVirus,Status,"Update Status"
        }
        $scriptblock3 = {
            param(
                $compname,

                $OperatingSystem
            )
            try{
                $vol = Get-WmiObject -ClassName Win32_Volume -ComputerName $compname -Filter "drivetype=3" -ErrorAction Stop
                   $DriveSpace = foreach ($drive in $vol){
                        if ($drive.driveletter -match "[A-Z]:") {
                            $size = "{0:N2}" -f ($drive.capacity / 1GB)
                            $freespace = "{0:N2}" -f ($drive.freespace / 1GB)
                            $props = @{
                                'ComputerName'=$compname;
                                'OS'=$OperatingSystem
                                'Drive'=$drive.name;
                                'Size(GB)'=$size;
                                'Freespace(GB)'=$freespace;
                                'Used Space(GB)'=[math]::round(($size - $freespace),2) 
                            }
                            $obj = New-Object -TypeName psobject -Property $props
                            $obj
                        }
                    }$DriveSpace
            }
            catch{
            }
        }
        #Setup Message Criteria
    }
    process{
        $computers = Get-ADComputer -Filter * -Properties LastLogonDate,OperatingSystem | where {$_.lastlogondate -GE $date}
        $TotalServers = $computers | where {$_.operatingsystem -Match "server"}    
        $TotalWorkstations = $computers | where {$_.operatingsystem -NotMatch "server"}
        #Check Which computers can be contacted
        foreach($comp in $computers) {
            $paramlist = @{
                Compname = $comp.name
                OperatingSystem = $comp.OperatingSystem
            }
            $runspace = [PowerShell]::Create()
            $null = $runspace.AddScript($scriptblock1)
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
        $workstations = $OnlineComps | where {$_.operatingsystem -NotMatch "server"}
        $servers = $OnlineComps | where {$_.operatingsystem -Match "server"}
        $ComputerSummary = @{
            "Total Servers" = $TotalServers.count
            "OnLine Servers" = $servers.count
            "Total Workstations" = $TotalWorkstations.count
            "OnLine Workstations" = $workstations.count
        }
        $AgentTotal = New-Object -TypeName psobject -Property $ComputerSummary
        #Check the AV Status on the workstations
        foreach($comp in $workstations) {
            $paramlist = @{
                Compname = $comp.name
                OperatingSystem = $comp.OperatingSystem
            }
            $runspace = [PowerShell]::Create()
            $null = $runspace.AddScript($scriptblock2)
            $null = $runspace.AddParameters($paramlist)
            $runspace.RunspacePool = $pool
            $runspaces += [PSCustomObject]@{ Pipe = $runspace; Status = $runspace.BeginInvoke() }
        }
        $AVStatusList = while ($runspaces.Status -ne $null){
            $completed = $runspaces | Where-Object { $_.Status.IsCompleted -eq $true }
            foreach ($runspace in $completed)
            {
                $runspace.Pipe.EndInvoke($runspace.Status)
                $runspace.Status = $null
            }
        }
        #Check the Drive Space for local drives on the servers
        foreach($comp in $servers) {
            $paramlist = @{
                Compname = $comp.name
                OperatingSystem = $comp.OperatingSystem
            }
            $runspace = [PowerShell]::Create()
            $null = $runspace.AddScript($scriptblock3)
            $null = $runspace.AddParameters($paramlist)
            $runspace.RunspacePool = $pool
            $runspaces += [PSCustomObject]@{ Pipe = $runspace; Status = $runspace.BeginInvoke() }
        }
        #Convert detected drive space into total space
        $ServerTotalSpace = @()
        $ServerDriveSpace = while ($runspaces.Status -ne $null){
            $completed = $runspaces | Where-Object { $_.Status.IsCompleted -eq $true }
            foreach ($runspace in $completed){
                $totalspace = 0
                $ServerTempSpace = $runspace.Pipe.EndInvoke($runspace.Status)
                    Foreach ($drive2 in $ServerTempSpace){
                        $totalspace += $drive2.("Used Space(GB)")
                    }
                $props2 = @{
                    'ComputerName' = $ServerTempSpace.ComputerName | select -Unique
                    'OS' = $ServerTempSpace.OS | select -Unique
                    'Total Used Space(GB)' = $totalspace
                }
                $obj2 = New-Object -TypeName psobject -Property $props2
                $ServerTotalSpace += $obj2
                $ServerTempSpace
                Clear-Variable totalspace,servertempspace
                $runspace.Status = $null
            }
        }
        #Prepare HTLM Content
        $precontent = "<img class='inc-logo' src='https://incaretechnologies.com/wp-content/uploads/InCare_Technologies_horizontal-NEW-NoCross-OUTLINES-for-Web.png'/><H1>$ClientName</H1>"
        $css = "https://incaretechnologies.com/css/incare.css"
        $b += $AgentTotal | select "Total Servers","OnLine Servers","Total Workstations","OnLine Workstations"| ConvertTo-Html -Fragment -PreContent "<h2>InCare Agent Count</h2>" | Out-String
        $b += $ServerTotalSpace | Select ComputerName,OS,"Total Used Space(GB)"| ConvertTo-Html -Fragment -PreContent "<h2>Total Used Space</h2>" | Out-String
        $b += $ServerDriveSpace | select ComputerName,Drive,"Size(GB)","Freespace(GB)","Used Space(GB)" | ConvertTo-Html -Fragment -PreContent "<h2>Server Disks:</h2>" | Out-String
        $b += $AVStatusList | ConvertTo-Html -Fragment -PreContent "<h2>AV Status</h2>" | Out-String
        $HTMLScratch = ConvertTo-Html -Title "InCare Inventory" -Head $precontent -CssUri $css -Body $b -PostContent "<H5><i>$(get-date)</i></H5>"
        $body = $HTMLScratch | Out-String
        $ServerTotalSpace | Export-Csv Servertotalspace.csv -NoTypeInformation
        $ServerDriveSpace | Export-Csv ServerDriveSpace.csv -NoTypeInformation
        $AVStatusList | Export-Csv AVStatusList.csv -NoTypeInformation
        #Prepare Credentials
        $login = "incaresales"
        $password = "Coffeeis4Clos3rz!@!@" | Convertto-SecureString -AsPlainText -Force
        $credentials = New-Object System.Management.Automation.Pscredential -Argumentlist $login,$password
        #Send Report
        $MailMessage = @{ 
            To = "$Email"
            From = "incare.analysis@incare360.com" 
            Subject = "InCare Audit for $ClientName" 
            Body = "$body"
            BodyAsHTML = $True
            Smtpserver = "notify.incare360.net"
            Credential = $credentials
            Attachments = ".\Servertotalspace.csv",".\ServerDriveSpace.csv",".\AVStatusList.csv"
        }
        Send-MailMessage @MailMessage

    }
    end{
        #Clean-up
        Remove-Item -Path .\Servertotalspace.csv -Force
        Remove-Item -Path .\ServerDriveSpace.csv -Force
        Remove-Item -Path .\AVStatusList.csv -Force
        $pool.Close()
        $pool.Dispose()
        #POP-UP for completion
        $scriptpu = New-Object -ComObject Wscript.Shell
        $scriptpu.popup("Analysis Complete",0,"Press OK",0x1)
    }
}
Get-ICAnalysis