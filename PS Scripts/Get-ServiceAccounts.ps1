﻿Function Get-ServiceAccounts{
    [cmdletbinding()]
        param(
            
        )
    Begin{
        Write-Verbose "Getting list of online servers"
        $onlineservers = @()
        $offlineservers = @()
        $allservers = Get-ADComputer -filter * -Properties operatingsystem | where {$_.operatingsystem -match "server" -and $_.enabled -eq $true}
        foreach ($server in $allservers){
            if (Test-Connection $server.name -Count 1 -Quiet){
                $onlineservers += $server
            }
            else{
                $offlineservers +=$server
            }
        }
    }
    Process{
        $dcomopt = New-CimSessionOption -Protocol Dcom
        $wsmanopt = New-CimSessionOption -Protocol Wsman
        Write-Verbose "Establishing Connection to servers"
        foreach($onlineserver in $onlineservers){
            Write-Verbose "Checking for WSMAN"
            If([bool](Test-WSMan -ComputerName $onlineserver.name)){
                try{
                    New-CimSession -ComputerName $onlineserver.name -SessionOption $wsmanopt -ErrorAction Stop 
                }
                catch{
                }
            }
            else{
                Write-Verbose "Attempting DCOM because WSMAN unavailable"
                try{
                    New-CimSession -ComputerName $onlineserver.name -SessionOption $dcomopt -ErrorAction Stop
                }
                catch{
                
                }
            }
        }
        Get-CimInstance -ClassName win32_service | select startname
    
    }
    End{
    
    }
}


Get-CimInstance win32_service | select name,startname,startmode