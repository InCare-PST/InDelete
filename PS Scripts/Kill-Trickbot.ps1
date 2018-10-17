# $verified = @('AD08','AD12','TRAINING','EX10-MBX-01','DATA08','CCPOS50','SS-5','GOLFSVR12','NETMOTION','PDTRAFFIC1','PDETECH1','WATER110','CCPOS30','FACMAINT','CCPOS10','PD2016-19','GISDB','PD2016-21','WATER2016-4','GARAGE100','PD2016-14','GOLF602','WATER2016-5','WATER2016-1','HRSAFETY','PD2016-6','PDTRAINOFC','ADMIN1','WATER2016-3','PD2016-11','PD2016-4','GOLF100','DISPATCH1','TB2016-1605','TB2016-1607','SQL08','PD2016-30','PD2016-15','FD110','PDDISPSUP','GOLF600','PDVIDEO','PDCOURT','GISWEB','CC102','GOLFPOS1','WATERS','WATER301','CC600','EX10-CAS-01','UTIL-1','GARAGENB','DISPATCH3','TB1303','DISPATCH2','GOLFPOS2','COURT140','GOLF605','ENGINEERING2','WATER680','GARAGE200','PD2016-7','PRCCOMCASH','GOLFPOS3','FDDUTY2016-4','GOLF101','PW2016-101','FDDUTY2016-3','SQL14','COURT120','DATA12','FDCAPT2016-4','GISSERVER','FDCAPT2016-3','CC22','TB-305','FDCAPT2016-5','MAYOR','FDDUTY2016-5','PD2016-ST5','PD2016-ST3','COGNITECH-PC','CCPOS20','GOLFMAINT','PDST2','PDWARRANTS','RACCLUB2','GOLF606','PW2016-20','RAQ7','CCPOS4','PD2016SGT1','TB400','PD2016SGT2','REV02','COURT130','MAYORASSIST','ARCSERVER08','TENNIS100','PD2016-10','PDBOOKING2','PD2016-3','PD2016SGT3','AINSLEY','PD2016-9','PD2016-5','RACCLUB1','PDPATROL3','PDETECH3','TS12','803SD42','PD2016-2','PDBOOKING','PD2016-17','CCPOS40','SEWER100','SEWER200','DISPATCH4','CC10','PDADMIN','AD12-BU','DESKTOP-TA9TN46','FD2017-5','FD2017-6','BLD2017-1','BLD2017-2','FD2017-7','FD2017-8','FDDUTY2017-2','CC2017-1','ADMIN2017-1','ADMIN2017-3','REV2017-1','BLD2017-3','COURT2017-1','COURT2017-2','COURT2017-3','COURT2017-4','COURT2017-5','LIB2017-1','LIB2017-2','LIB2017-3','LIB2017-4','LIB2017-5','LIB2017-6','LIB2017-7','LIB2017-9','LIB2017-10','WATER2017-1','LIB2017-11','WATER2017-2','WATER2017-3','ENG2017-1','CITYMGR2017','FDCAPT2017-2','CCPOS2017-1','CCPOSTAB1','CCPOS2017-2','CCPOS2017-3','CCPOS2017-4','CCPOS2017-5','CCPOSTAB3','CCPOS2017-6','CCPOS2017-13','RECCTR2017-1','ALOGIC','PARK2','PARK1','PDREC2017-1','PDREC2017-2','PDETOFFICE1','TB2017-3B','GIS2017-1','LIBSHUTTLE1','LIBSHUTTLE2','LIBSHUTTLE3','LIBSHUTTLE4','PUBWORKS2018LT','FDTRAIN2018-1','WEB12','CC2018-4','FIRE2018-2','CC2018-3','CC2018-5','CC2018-','CC2018-7','CC2018-8','GOLF2018-2','LIB2018-1','ACCESS','CC2018-1','STARTER','COURT110','ITMGR2018','WATER2017-100','TB155','FIREBAT2017','CC2018-2','REV2017-4')

$outfile = "C:\WindowsPowershell\quicklog.txt"
# $filenames = @('mttvca.exe','mssvca.exe','44783m8uh77g8l8_nkubyhu5vfxxbh878xo6hlttkppzf28tsdu5kwppk_11c1jl.exe')

$loop = 6

while ($loop -gt 0){
"=======================================================
Scan Loop $loop
" | Out-File $outfile -Append
Get-Date | Out-File $outfile -Append
"
=======================================================
" | Out-File $outfile -Append

    ForEach ($computer in $verified) {
        $outfile = "C:\WindowsPowershell\quicklog.txt"
        $response = @()
        Write-Host $computer " " (Get-Date -f 'yyyy-MM-dd hh:mm:ss')
        Invoke-Command -ComputerName $computer {
            $path1 = "C:\*"
            $path2 = "C:\Users\*"
            $path3 = "C:\Windows\*"
            $comp = $env:COMPUTERNAME
            # $filenames = @('mttvca.exe','mssvca.exe','44783m8uh77g8l8_nkubyhu5vfxxbh878xo6hlttkppzf28tsdu5kwppk_11c1jl.exe')
            $filelengths = @(578690)
            Write-Host $path1
            $files = Get-ChildItem -Path $path1 -Filter {LastWriteTime -ge (Get-Date).AddHours(-24) -and -not $_.PSIsContainer} -Include *.dll,*.ocx,*.exe
            $files | Select -First 1 | fl
          #  $files | Select Name, Path, LastWriteTime

            Write-Host $path2
            $files = Get-ChildItem -Path $path2 -Recurse -Filter {LastWriteTime -ge (Get-Date).AddHours(-24) -and -not $_.PSIsContainer} -Include "*.dll","*.ocx","*.exe"
            $files | Select -First 1 | fl
          # $files | Select Name, Path, LastWriteTime
     <#           $files = Get-Item -Path "$path2\$filename" -ErrorAction SilentlyContinue 
		        ForEach ($file in $files) {
                    If ([bool]$file) {
                        
                        Stop-Process -Name $file.basename -ErrorAction SilentlyContinue  -Force
                        Start-Sleep -Seconds 3
			            $file.Delete() 
                       <# 
                        $response += "Found File on $comp : $filename at $path2
" 
                    }
		        }
       #>       Write-Host $path3
                $files = Get-ChildItem -Path $path3 -Filter {LastWriteTime -ge (Get-Date).AddHours(-24) -and -not $_.PSIsContainer} -Include *.dll,*.ocx,*.exe
                $files | Select -First 1 | fl
             #  $files | Select Name, Path, LastWriteTime
       <#         $files = Get-Item -Path "$path3\$filename" -ErrorAction SilentlyContinue 
		        ForEach ($file in $files) {
                    If ([bool]$file) {

                        Stop-Process -Name $file.basename -ErrorAction SilentlyContinue -Force
                        Start-Sleep -Seconds 3
			            $file.Delete() 
                        <# 
                        $response += "Found File on $comp : $filename at $path3
" 
                    }
		        }
                $files = Get-Item -Path "$path4\$filename" -ErrorAction SilentlyContinue 
		        ForEach ($file in $files) {
                    If ([bool]$file) {

                        Stop-Process -Name $file.basename -ErrorAction SilentlyContinue -Force
                        Start-Sleep -Seconds 3
			            $file.Delete() 
                    
                        $response += "Found File on $comp : $filename at $path4
" 
                    }
		        }
           
            }#>
            Return $response
	    } | Out-File $outfile -Append
    }
    $loop -= 1
}





& \WindowsPowerShell\verify-for-trickbot.ps1