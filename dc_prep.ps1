#start logging
$null = Start-Transcript -Append $env:TEMP\dc_prep.log
Write-Host $(Get-Date)"[INFO]Start Logging to $env:TEMP\dc_prep.log"

#check if current machine is domaincontroller
$ComputerType = (Get-WmiObject -Class Win32_OperatingSystem).producttype #1 = Workstation | 2 = DomainController | 3 = Server
if ($ComputerType -ne "2") {
    Write-Host $(Get-Date)"[ERROR] Current Machine is not a Domaincontroller!" -ForegroundColor Red
    pause
    exit
}
else {
    $domainname = (Get-ADDomain).DistinguishedName
    Write-Host $(Get-Date)"[INFO] Current Machine is a Domaincontroller of $domainname" -ForegroundColor Green
}
#prepare object for better downloading
$wc = New-Object net.webclient

#read configfile if available
$configfilepath = "$($pwd.path)\dc_prep.conf"
$configfile = Test-Path $configfilepath
if ($configfile -eq "True") {
    Write-Host $(Get-Date)"[INFO] Configfile found. Configuration is read from file"
    $customer_name = (Get-Content $configfilepath)[0].Substring(16)
    $datev = (Get-Content $configfilepath)[1].Substring(16)
    $adconnect = (Get-Content $configfilepath)[2].Substring(16)
    $share_drive = (Get-Content $configfilepath)[3].Substring(16)
    $FSLogix = (Get-Content $configfilepath)[4].Substring(16)
} 
else {
    Write-Host $(Get-Date)"[INFO] No configfile found. Parameters have to be defined manually"
    $customer_name = Read-Host "Customer Name"
    $datev = Read-Host "Is this going to be a DATEV Fileserver? [y/n]"
    while(1 -ne 2)
    {
        if ($datev -eq "y") {write-host "datev preparations are going to be configured.";break} 
        if ($datev -eq "n") {write-host "no datev specific preperations are going to be configured.";break}
        else {$datev = Read-Host "Is this going to be a DATEV Fileserver? [y/n]"}
    }
    $adconnect = Read-Host "Configure Azure-AD-Connect?"
    while(1 -ne 2)
    {
        if ($adconnect -eq "y") {write-host "Azure-AD-Connect is going to be configured";break} 
        if ($adconnect -eq "n") {write-host "Azure-AD-Connect is NOT going to be configured";break}
        else {$adconnect = Read-Host "Configure Azure-AD-Connect? [y/n]"}
    }
    $FSLogix = Read-Host "Configure FSLogix?"
    while(1 -ne 2)
    {
        if ($FSLogix -eq "y") {write-host "FSLogix is going to be configured";break} 
        if ($FSLogix -eq "n") {write-host "FSLogix is NOT going to be configured";break}
        else {$FSLogix = Read-Host "Configure FSLogix? [y/n]"}
    }
    $share_drive = Read-Host "On which Drive are the SMB-Shares going to be saved? syntax: C:"
}


function create_shares {
    mkdir $share_drive\_FREIGABEN    
}
function create_ad_ou {
    New-ADOrganizationalUnit -Name $customer_name -Path $domainname
    New-ADOrganizationalUnit -Name Benutzer -Path "OU=$customer_name,$domainname"
    New-ADOrganizationalUnit -Name Gruppen -Path "OU=$customer_name,$domainname"
    New-ADOrganizationalUnit -Name Computer -Path "OU=$customer_name,$domainname"
    New-ADOrganizationalUnit -Name Terminalserver -Path "OU=Computer,OU=$customer_name,$domainname"
}

function create_ad_centralstore {
    copy-item C:\Windows\PolicyDefinitions \\localhost\sysvol\$((Get-ADDomain).DNSRoot)\Policies\
}

function create_ad_policies { 
    New-GPO -Name Netzlaufwerke
    New-GPLink -Name "Netzlaufwerke" -Target "$domainname"
    New-GPO -Name EdgeDisableFirstRun
    New-GPLink -Name "EdgeDisableFirstRun" -Target "$domainname"
    Set-GPRegistryValue -Name 'EdgeDisableFirstRun' -Key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge' -ValueName 'hidefirstrunexperience' -Type DWord -Value 1
    Set-GPRegistryValue -Name 'EdgeDisableFirstRun' -Key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge' -ValueName 'showrecommendationsenabled' -Type DWord -Value 0
}

function datev {
    New-ADGroup -Name "DATEVUSER" -SamAccountName DATEVUSER -GroupCategory Security -GroupScope Global -DisplayName "DATEVUSER" -Path "OU=Gruppen,OU=$customer_name,$domainname"
    $wc.Downloadfile("https://download.datev.de/download/datevitfix/serverprep.exe", "C:\Users\$env:USERNAME\Downloads\serverprep.exe")
    mkdir $share_drive\_FREIGABEN\WINDVSW1
    mkdir $share_drive\_FREIGABEN\WINDVSW1\CONFIGDB
    
}

function adconnect {
    New-ADGroup -Name "M365-AD-Connect" -SamAccountName M365-AD-Connect -GroupCategory Security -GroupScope Global -DisplayName "M365-AD-Connect" -Path "OU=Gruppen,OU=$customer_name,$domainname"
    $wc.Downloadfile("https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi", "C:\Users\$env:USERNAME\Downloads\AzureADConnect.exe")
}

function fslogix {
    mkdir "$share_drive\_FREIGABEN\FSLogix_Container"
    $wc.Downloadfile("https://download.microsoft.com/download/c/4/4/c44313c5-f04a-4034-8a22-967481b23975/FSLogix_Apps_2.9.8440.42104.zip", "C:\Users\$env:USERNAME\Downloads\FSLogix_Apps.exe")
    New-GPO -Name FSLogix
    New-GPLink -Name "FSLogix" -Target "OU=Terminalserver,OU=Computer,OU=$customer_name,$domainname"
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Logging' -ValueName 'LogFileKeepingPeriod' -Type DWord -Value 7
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'Enabled' -Type DWord -Value 1
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'IsDynamic' -Type DWord -Value 1
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'ProfileType' -Type DWord -Value 3
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'SizeInMBs' -Type DWord -Value 30000
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'VHDLocations' -Type SZ -Value "\\$([System.Net.Dns]::GetHostByName($env:computerName).HostName)\FSLogix_Container"
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'LockedRetryCount' -Type DWord -Value 12
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'VolumeType' -Type SZ -Value VHDX
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'FlipFlopProfileDirectoryName' -Type DWord -Value 1
}

#check if successfull
function check {
    $exitcode = 0
    if([adsi]::Exists("LDAP://OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] OU=$customer_name,$domainname creation failed"; $exitcode +1}
    if([adsi]::Exists("LDAP://OU=Benutzer,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] OU=Benutzer,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] OU=Benutzer,OU=$customer_name,$domainname creation failed"; $exitcode +1}
    if([adsi]::Exists("LDAP://OU=Gruppen,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] OU=Gruppen,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] OU=Gruppen,OU=$customer_name,$domainname creation failed"; $exitcode +1}
    if([adsi]::Exists("LDAP://OU=Computer,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] OU=Computer,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] OU=Computer,OU=$customer_name,$domainname creation failed"; $exitcode +1}
    if([adsi]::Exists("LDAP://OU=Terminalserver,OU=Computer,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] OU=Terminalserver,OU=Computer,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] OU=Terminalserver,OU=Computer,OU=$customer_name,$domainname creation failed"; $exitcode +1}
    if ($datev -eq "y") { if([adsi]::Exists("LDAP://CN=DATEVUSER,OU=Gruppen,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] CN=DATEVUSER,OU=Gruppen,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] CN=DATEVUSER,OU=Gruppen,OU=$customer_name,$domainname creation failed"; $exitcode +1}}
    if ($datev -eq "y") { if(test-path $share_drive\_FREIGABEN\WINDVSW1\CONFIGDB -eq $True) {Write-Host $(Get-Date)"[Info] Folder $share_drive\_FREIGABEN\WINDVSW1\CONFIGDB successfully created"} else {Write-Host $(Get-Date)"Folder creation failed"; $exitcode +1}}
    if ($adconnect -eq "y") { if([adsi]::Exists("LDAP://CN=M365-AD-Connect,OU=Gruppen,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] CN=M365-AD-Connect,OU=Gruppen,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] CN=M365-AD-Connect,OU=Gruppen,OU=$customer_name,$domainname creation failed"; $exitcode +1}}
    if ((Get-GPO -Name Netzlaufwerke) -ne "" ) {Write-Host $(Get-Date)"[Info] GPO Netzlaufwerke successfully created"} else {Write-Host $(Get-Date)"[ERROR] GPO Netzlaufwerke creation failed"; $exitcode +1}
    if ((Get-GPO -Name EdgeDisableFirstRun) -ne "" ) {Write-Host $(Get-Date)"[Info] GPO EdgeDisableFirstRun successfully created"} else {Write-Host $(Get-Date)"[ERROR] GPO EdgeDisableFirstRun creation failed"; $exitcode +1}
    if ($exitcode -eq 0) {
        Write-Host $(Get-Date)"[INFO] The Script encountered no errors."
    }
    else {
        Write-Host $(Get-Date)"[ERROR] The Script encountered $exitcode errors. Please check the Log" -ForegroundColor Red
    }
}

#run script as specified
create_ad_ou
create_ad_policies
create_ad_centralstore
if ($datev -eq "y") {datev}
if ($adconnect -eq "y") {adconnect}
if ($FSLogix -eq "y") {fslogix}
check
