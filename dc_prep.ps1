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

# activate ad recyclebin
Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADDomain).Forest -Confirm:$false


function create_shares {
    mkdir $share_drive\_FREIGABEN    
}
function create_ad_ou {
    try {New-ADOrganizationalUnit -Name $customer_name -Path $domainname} catch {Write-Host "Either "OU=$customer_name,$domaeinname" already exists or an error occured creating it; $exitcode +1"}
    try {New-ADOrganizationalUnit -Name Benutzer -Path "OU=$customer_name,$domainname"} catch {Write-Host "Either "OU=Benutzer,OU=$customer_name,$domainname" already exists or an error occured creating it; $exitcode +1"}
    try {New-ADOrganizationalUnit -Name Gruppen -Path "OU=$customer_name,$domainname"} catch {Write-Host "Either "OU=Gruppen,OU=$customer_name,$domainname" already exists or an error occured creating it; $exitcode +1"}
    try {New-ADOrganizationalUnit -Name Computer -Path "OU=$customer_name,$domainname"} catch {Write-Host "Either "OU=Computer,OU=$customer_name,$domainname" already exists or an error occured creating it; $exitcode +1"}
    try {New-ADOrganizationalUnit -Name Terminalserver -Path "OU=Computer,OU=$customer_name,$domainname"} catch {Write-Host "Either "OU=Terminalserver,OU=Computer,OU=$customer_name,$domainname" already exists or an error occured creating it; $exitcode +1"}
}

function create_ad_centralstore {
    copy-item C:\Windows\PolicyDefinitions \\localhost\sysvol\$((Get-ADDomain).DNSRoot)\Policies\ -Recurse
}

function create_ad_policies { 
    New-GPO -Name Netzlaufwerke | Out-Null
    New-GPLink -Name "Netzlaufwerke" -Target "$domainname"
    New-GPO -Name EdgeDisableFirstRun | Out-Null
    New-GPLink -Name "EdgeDisableFirstRun" -Target "$domainname"
    Set-GPRegistryValue -Name 'EdgeDisableFirstRun' -Key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge' -ValueName 'hidefirstrunexperience' -Type DWord -Value 1
    Set-GPRegistryValue -Name 'EdgeDisableFirstRun' -Key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge' -ValueName 'showrecommendationsenabled' -Type DWord -Value 0
}

function datev {
    try {New-ADGroup -Name "DATEVUSER" -SamAccountName DATEVUSER -GroupCategory Security -GroupScope Global -DisplayName "DATEVUSER" -Path "OU=Gruppen,OU=$customer_name,$domainname"} 
    catch {Move-ADObject -Identity $((get-adgroup DATEVUSER).ObjectGUID | ForEach{$_.GUID}) -TargetPath "OU=Gruppen,OU=$customer_name,$domainname"}
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
    #check universial name for Everyone group and create SMB Share
    $everyoneSID = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
    $everyoneName = $everyoneSID.Translate([System.Security.Principal.NTAccount]).Value
    $FSLogixShareParams = @{
    Name = "FSLogix_Container"
    Path = "$share_drive\_FREIGABEN\FSLogix_Container"
    FullAccess = $everyoneName
    }
    New-SmbShare @FSLogixShareParams
    #set NTFS ACLs for FSLogix Share
    $FSLogixACL = Get-Acl -Path "$share_drive\_FREIGABEN\FSLogix_Container"
    $FSLogixACL.SetAccessRuleProtection($true, $false)
    $SYSTEMAccount = $([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')).Translate([System.Security.Principal.NTAccount]).Value
    $CREATOROWNERAccount = $([System.Security.Principal.SecurityIdentifier]::new('S-1-3-0')).Translate([System.Security.Principal.NTAccount]).Value
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlag0 = [System.Security.AccessControl.PropagationFlags]::InheritOnly
    $PropagationFlag1 = [System.Security.AccessControl.PropagationFlags]::None
    $SpecialRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::AppendData -bor [System.Security.AccessControl.FileSystemRights]::CreateDirectories 
    $FSLogixAccessRule0 = New-Object System.Security.AccessControl.FileSystemAccessRule("$CREATOROWNERAccount","FullControl","$InheritanceFlag","$PropagationFlag0","Allow")
    $FSLogixAccessRule1 = New-Object System.Security.AccessControl.FileSystemAccessRule("$((Get-ADDomain).NetBIOSName)\Domänen-Admins","FullControl","$InheritanceFlag","$PropagationFlag1","Allow")
    $FSLogixAccessRule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("$((Get-ADDomain).NetBIOSName)\Domänen-Benutzer","$SpecialRights","Allow")
    $FSLogixAccessRule3 = New-Object System.Security.AccessControl.FileSystemAccessRule("$SYSTEMAccount","FullControl","$InheritanceFlag","$PropagationFlag1","Allow")
    $FSLogixACL.SetAccessRule($FSLogixAccessRule0)
    $FSLogixACL.SetAccessRule($FSLogixAccessRule1)
    $FSLogixACL.SetAccessRule($FSLogixAccessRule2)
    $FSLogixACL.SetAccessRule($FSLogixAccessRule3)
    Set-Acl -Path "$share_drive\_FREIGABEN\FSLogix_Container -AclObject" $FSLogixACL
    #download FSLogix Apps and add centralstore admx/adml
    $wc.Downloadfile("https://aka.ms/fslogix_download", "C:\Users\$env:USERNAME\Downloads\FSLogix_Apps.zip")
    Expand-Archive -LiteralPath "C:\Users\$env:USERNAME\Downloads\FSLogix_Apps.zip" -DestinationPath "C:\Users\$env:USERNAME\Downloads\FSLogix_Apps"
    copy-item C:\Users\$env:USERNAME\Downloads\FSLogix_Apps\FSLogix*\fslogix.admx \\localhost\sysvol\$((Get-ADDomain).DNSRoot)\Policies\PolicyDefinitions
    copy-item C:\Users\$env:USERNAME\Downloads\FSLogix_Apps\FSLogix*\fslogix.adml \\localhost\sysvol\$((Get-ADDomain).DNSRoot)\Policies\PolicyDefinitions\de-DE
    copy-item C:\Users\$env:USERNAME\Downloads\FSLogix_Apps\FSLogix*\fslogix.adml \\localhost\sysvol\$((Get-ADDomain).DNSRoot)\Policies\PolicyDefinitions\en-US
    #install FSLogix on every Terminalserver found in the AD and add domainadmins to exclude group
    $serversWithRDSWithoutADDS = Get-ADComputer -Filter {OperatingSystem -like '*server*'} | ForEach-Object {
    $server = $_.Name
    $rdsInstalled = Get-WindowsFeature -ComputerName $server -Name "Remote-Desktop-Services" | Where-Object {$_.Installed -eq $true }
    $addsInstalled = Get-WindowsFeature -ComputerName $server -Name "AD-Domain-Services" | Where-Object {$_.Installed -eq $true }
    if ($rdsInstalled -and -not $addsInstalled) {
        $server
        }
    }
    $serversWithRDSWithoutADDS
    ForEach ($RDS in $serversWithRDSWithoutADDS) {
        Invoke-Command -ComputerName WTS1 -ScriptBlock {
        $random = random
        $wc = New-Object net.webclient
        $wc.Downloadfile("https://aka.ms/fslogix_download", "C:\Users\$env:USERNAME\Downloads\FSLogix_Apps.zip")
        if (test-path "C:\Users\$env:USERNAME\Downloads\FSLogix_Apps") {ren "C:\Users\$env:USERNAME\Downloads\FSLogix_Apps" "C:\Users\$env:USERNAME\Downloads\FSLogix_Apps_OLD_$random"}
        Expand-Archive -LiteralPath "C:\Users\$env:USERNAME\Downloads\FSLogix_Apps.zip" -DestinationPath "C:\Users\$env:USERNAME\Downloads\FSLogix_Apps"
        Set-Location "C:\Users\$env:USERNAME\Downloads\FSLogix_Apps\*\x64\Release\"
        $fsxinst = (get-childitem).name
        $fsxinst
        ForEach ($prog in $fsxinst) {
            cmd /c $prog /install /quiet
            }
        }
        Add-LocalGroupMember -Group "FSLogix Profile Exclude List" -Member "DOMAENE\Domänen-Admins" #FIXME: use universial name/guid for Member
    }
    #add FSLogix GPOs
    New-GPO -Name FSLogix
    New-GPLink -Name "FSLogix" -Target "OU=Terminalserver,OU=Computer,OU=$customer_name,$domainname"
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Logging' -ValueName 'LogFileKeepingPeriod' -Type DWord -Value 7
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'Enabled' -Type DWord -Value 1
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'IsDynamic' -Type DWord -Value 1
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'ProfileType' -Type DWord -Value 3
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'SizeInMBs' -Type DWord -Value 30000
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'VHDLocations' -Type String -Value "\\$([System.Net.Dns]::GetHostByName($env:computerName).HostName)\FSLogix_Container"
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'LockedRetryCount' -Type DWord -Value 12
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'VolumeType' -Type String -Value VHDX
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'FlipFlopProfileDirectoryName' -Type DWord -Value 1
}

#check if successfull
function check {
    $exitcode = 0
    if ((Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"').EnabledScopes) {Write-Host $(Get-Date)"[Info] Active Directory Recycle Bin successfully activated"} else {Write-Output $(Get-Date)"[ERROR] Active Directory Recycle Bin was not activated" -ForegroundColor Red; $exitcode +1}
    if([adsi]::Exists("LDAP://OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] OU=$customer_name,$domainname creation failed" -ForegroundColor Red; $exitcode +1}
    if([adsi]::Exists("LDAP://OU=Benutzer,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] OU=Benutzer,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] OU=Benutzer,OU=$customer_name,$domainname creation failed" -ForegroundColor Red; $exitcode +1}
    if([adsi]::Exists("LDAP://OU=Gruppen,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] OU=Gruppen,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] OU=Gruppen,OU=$customer_name,$domainname creation failed" -ForegroundColor Red; $exitcode +1}
    if([adsi]::Exists("LDAP://OU=Computer,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] OU=Computer,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] OU=Computer,OU=$customer_name,$domainname creation failed" -ForegroundColor Red; $exitcode +1}
    if([adsi]::Exists("LDAP://OU=Terminalserver,OU=Computer,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] OU=Terminalserver,OU=Computer,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] OU=Terminalserver,OU=Computer,OU=$customer_name,$domainname creation failed" -ForegroundColor Red; $exitcode +1}
    if ($datev -eq "y") { if([adsi]::Exists("LDAP://CN=DATEVUSER,OU=Gruppen,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] CN=DATEVUSER,OU=Gruppen,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] CN=DATEVUSER,OU=Gruppen,OU=$customer_name,$domainname creation failed" -ForegroundColor Red; $exitcode +1}}
    if ($datev -eq "y") { if(test-path $share_drive\_FREIGABEN\WINDVSW1\CONFIGDB) {Write-Host $(Get-Date)"[Info] Folder $share_drive\_FREIGABEN\WINDVSW1\CONFIGDB successfully created"} else {Write-Host $(Get-Date)"Folder creation failed" -ForegroundColor Red; $exitcode +1}}
    if ($adconnect -eq "y") { if([adsi]::Exists("LDAP://CN=M365-AD-Connect,OU=Gruppen,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] CN=M365-AD-Connect,OU=Gruppen,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] CN=M365-AD-Connect,OU=Gruppen,OU=$customer_name,$domainname creation failed" -ForegroundColor Red; $exitcode +1}}
    if ((Get-GPO -Name Netzlaufwerke) -ne "" ) {Write-Host $(Get-Date)"[Info] GPO Netzlaufwerke successfully created"} else {Write-Host $(Get-Date)"[ERROR] GPO Netzlaufwerke creation failed" -ForegroundColor Red; $exitcode +1}
    if ((Get-GPO -Name EdgeDisableFirstRun) -ne "" ) {Write-Host $(Get-Date)"[Info] GPO EdgeDisableFirstRun successfully created"} else {Write-Host $(Get-Date)"[ERROR] GPO EdgeDisableFirstRun creation failed" -ForegroundColor Red; $exitcode +1}
    if (test-path \\localhost\sysvol\$((Get-ADDomain).DNSRoot)\Policies\PolicyDefinitions) {Write-Host $(Get-Date)"[Info] centralstore successfully created"} else {Write-Host $(Get-Date)"[Info] centralstore successfully failed" -ForegroundColor Red; $exitcode +1}
    if ($exitcode -eq 0) {
        Write-Host $(Get-Date)"[INFO] The Script encountered no errors." -ForegroundColor Green
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
