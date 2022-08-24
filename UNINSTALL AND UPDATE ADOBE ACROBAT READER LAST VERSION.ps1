<#by. Jose R.#>

$validatepath = Test-Path "C:\Program Files (x86)\Adobe\Acrobat Reader DC"
if($validatepath = $true)
{
$RegUninstallPaths = 
@(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)

Get-CimInstance -ClassName 'Win32_Process' | Where-Object {$_.ExecutablePath -like '*C:\Program Files (x86)\Adobe\Acrobat Reader DC*'} | 
    Select-Object @{n='Name';e={$_.Name.Split('.')[0]}} | Stop-Process -Force
 
Get-process -Name *iexplore* | Stop-Process -Force -ErrorAction SilentlyContinue

$UninstallSearchFilter = {($_.GetValue('DisplayName') -like '*Adobe Acrobat Reader*') -and (($_.GetValue('Publisher') -eq 'Adobe')) -and ($VersionsToKeep -notcontains $_.GetValue('DisplayName'))}

# Uninstall unwanted Java versions and clean up program files
 
foreach ($Path in $RegUninstallPaths) {
    if (Test-Path $Path) {
        Get-ChildItem $Path | Where-Object $UninstallSearchFilter | 
       foreach { 
           
        Start-Process 'C:\Windows\System32\msiexec.exe' "/X$($_.PSChildName) /qn" -Wait
    
        }
    }
}
}


$validatepath1 = Test-Path "C:\​Program Files (x86)\​Adobe\​Reader 11.0\​Reader"
if($validatepath1 = $true)
{
$RegUninstallPaths = 
@(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)

Get-CimInstance -ClassName 'Win32_Process' | Where-Object {$_.ExecutablePath -like '*C:\​Program Files (x86)\​Adobe\​Reader 11.0\​Reader​*'} | 
    Select-Object @{n='Name';e={$_.Name.Split('.')[0]}} | Stop-Process -Force
 
Get-process -Name *iexplore* | Stop-Process -Force -ErrorAction SilentlyContinue

$UninstallSearchFilter = {($_.GetValue('DisplayName') -like '*Adobe Acrobat Reader*') -and (($_.GetValue('Publisher') -eq 'Adobe')) -and ($VersionsToKeep -notcontains $_.GetValue('DisplayName'))}

# Uninstall unwanted Java versions and clean up program files
 
foreach ($Path in $RegUninstallPaths) {
    if (Test-Path $Path) {
        Get-ChildItem $Path | Where-Object $UninstallSearchFilter | 
       foreach { 
           
        Start-Process 'C:\Windows\System32\msiexec.exe' "/X$($_.PSChildName) /qn" -Wait
    
        }
    }
}
}

$validatepath3 = Test-Path "C:\​Program Files (x86)\​Adobe\​Reader 10.0\​Reader"
if($validatepath3 = $true)
{
$RegUninstallPaths = 
@(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)

Get-CimInstance -ClassName 'Win32_Process' | Where-Object {$_.ExecutablePath -like '*C:\​Program Files (x86)\​Adobe\​Reader 10.0\​Reader*'} | 
    Select-Object @{n='Name';e={$_.Name.Split('.')[0]}} | Stop-Process -Force
 
Get-process -Name *iexplore* | Stop-Process -Force -ErrorAction SilentlyContinue

$UninstallSearchFilter = {($_.GetValue('DisplayName') -like '*Adobe Acrobat Reader*') -and (($_.GetValue('Publisher') -eq 'Adobe')) -and ($VersionsToKeep -notcontains $_.GetValue('DisplayName'))}

# Uninstall unwanted Java versions and clean up program files
 
foreach ($Path in $RegUninstallPaths) {
    if (Test-Path $Path) {
        Get-ChildItem $Path | Where-Object $UninstallSearchFilter | 
       foreach { 
           
        Start-Process 'C:\Windows\System32\msiexec.exe' "/X$($_.PSChildName) /qn" -Wait
    
        }
    }
}
}


Sleep -Seconds 10

#Generalizacion de instalacion a todos los equipos 
#Descargar Acrobat Reader DC
#Proceso de instslacion de Open office
$uri = "https://ardownload2.adobe.com/pub/adobe/reader/win/AcrobatDC/2200120142/AcroRdrDC2200120142_es_ES.exe"
$out= "c:\AcroRdrDC2200120142_es_ES.exe"
Invoke-WebRequest -uri $uri -OutFile $out

Start-Process -FilePath "$out" -ArgumentList "/sAll /rs /msi EULA_ACCEPT=YES"

Sleep -Seconds 60

Remove-Item "$out"

exit 8
