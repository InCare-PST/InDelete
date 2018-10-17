$date = (get-date).AddDays(-210)
Get-ADComputer -Filter * -Properties LastLogonDate | where lastlogondate -GE $date | Export-Csv c:\temp\active_computers.csv
