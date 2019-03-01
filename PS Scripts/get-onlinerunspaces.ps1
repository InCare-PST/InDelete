$date = (get-date).AddDays(-60)
$computers = Get-ADComputer -Filter * -Properties LastLogonDate | where lastlogondate -GE $date
$pool = [RunspaceFactory]::CreateRunspacePool(1, [int]$env:NUMBER_OF_PROCESSORS + 1000)
$pool.ApartmentState = "MTA"
$pool.Open()
$runspaces = @()
$scriptblock = {
    Param(
        $Comp
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
            PsRemoting = $WSMAN
        }
    }
    $obj = New-Object -TypeName psobject -Property $tempobj
    $obj | select Name,PsRemoting
}

foreach($comp in $computers) {
    #Write-host "$comp temp"
    $runspace = [PowerShell]::Create()
    $null = $runspace.AddScript($scriptblock)
    $null = $runspace.AddArgument($comp.name)
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

$PsRemotingEnabled = $onlinecomps.where({$_.PsRemoting -eq "Enabled"})
$PsRemotingDisabled = $onlinecomps.where({$_.PsRemoting -eq "Disabled"})
Write-Output "$($onlinecomps.count) have been detected online"
Write-Output "$($PsRemotingEnabled.count) are responding via PSRemote"
Write-Output "$($PsRemotingDisabled.count) need to have PSRemoting enabled or addressed"

$pool.Close()
$pool.Dispose()
