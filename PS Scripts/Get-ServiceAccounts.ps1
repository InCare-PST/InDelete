Function Get-ServiceAccounts{
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
        $wsmanerrors = @()
        $dcomerrors = @()
        Write-Verbose "Establishing Connection to servers"
        foreach($onlineserver in $onlineservers){
            Write-Verbose "Checking for WSMAN"
            If([bool](Test-WSMan -ComputerName $onlineserver.name)){
                try{
                    Write-Verbose "Attempting to connect to $onlineserver via WSMAN"
                    New-CimSession -ComputerName $onlineserver.name -SessionOption $wsmanopt -ErrorAction Stop 
                }
                catch{
                }
            }
            else{
                Write-Verbose "Attempting DCOM because WSMAN unavailable"
                try{
                    Write-Verbose "Attempting to connect to $onlineserver via DCOM"
                    New-CimSession -ComputerName $onlineserver.name -SessionOption $dcomopt -ErrorAction Stop
                }
                catch{
                
                }
            }
        }NetworkService
        Get-CimInstance -CimSession (Get-CimSession) -ClassName win32_service | where {$_.startname -notmatch "local|NetworkService" -and $_.StartName -ne $null}
    
    }
    End{
    
    }
}


Get-CimInstance win32_service | select name,startname,startmode