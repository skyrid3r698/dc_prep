#Define Parameters
Param(
    [bool]$debug = $False
)

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
    if ($customer_name -eq "false") {
    while(1 -ne 2)
    {
        if ($adconnect -eq "y") {write-host "Setup is continuing with $customer_name as main OU";break} 
        if ($adconnect -eq "n") {write-host "please set correct customer name in configfile";pause;exit}
        else {$adconnect = Read-Host "Customer name is set to $customer_name. Are you sure you want to configure your main OU with that name? [y/n]"}
    }
    }
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

#read extra needed variables
$domainnameshort = (Get-ADDomain).NetBIOSName
$GRPAdministrators = (get-adgroup -Identity S-1-5-32-544).Name
$GRPDomainAdmins = (Get-ADgroup -Identity "$((get-addomain).DomainSID.Value)-512").Name
$GRPDomainUsers = (Get-ADgroup -Identity "$((get-addomain).DomainSID.Value)-513").Name
$existingGPO = (get-gpo -All).DisplayName
$existingGroups = (Get-ADGroup -Filter *).Name
$SYSTEMAccount = $([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')).Translate([System.Security.Principal.NTAccount]).Value
$CREATOROWNERAccount = $([System.Security.Principal.SecurityIdentifier]::new('S-1-3-0')).Translate([System.Security.Principal.NTAccount]).Value


# activate ad recyclebin
if ((Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"').EnabledScopes) {
if ($debug -eq $True) {Write-Host "debug: ActiceDirectory Recycle Bin already activated" -ForegroundColor Yellow}
}
else {
Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADDomain).Forest -Confirm:$false
}

#create share location on $share_drive
function create_shares {
    if (Test-Path $share_drive\_FREIGABEN) {if ($debug -eq $True) {Write-Host "debug: $share_drive\_FREIGABEN already exists" -ForegroundColor Yellow}} else {mkdir $share_drive\_FREIGABEN}
}
#create OUs
function create_ad_ou {
    try {Get-ADOrganizationalUnit -Identity "OU=$customer_name,$domainname" > $null; if ($debug -eq $True) {Write-Host "debug: OU=$customer_name,$domainname already exists" -ForegroundColor Yellow}} catch {New-ADOrganizationalUnit -Name $customer_name -Path $domainname}
    try {Get-ADOrganizationalUnit -Identity "OU=Benutzer,OU=$customer_name,$domainname" > $null; if ($debug -eq $True) {Write-Host "debug: OU=Benutzer,OU=$customer_name,$domainname already exists" -ForegroundColor Yellow}} catch {New-ADOrganizationalUnit -Name Benutzer -Path "OU=$customer_name,$domainname"}
    try {Get-ADOrganizationalUnit -Identity "OU=Gruppen,OU=$customer_name,$domainname" > $null; if ($debug -eq $True) {Write-Host "debug: OU=Gruppen,OU=$customer_name,$domainname already exists" -ForegroundColor Yellow}} catch {New-ADOrganizationalUnit -Name Gruppen -Path "OU=$customer_name,$domainname"}
    try {Get-ADOrganizationalUnit -Identity "OU=Computer,OU=$customer_name,$domainname" > $null; if ($debug -eq $True) {Write-Host "debug: OU=Computer,OU=$customer_name,$domainname already exists" -ForegroundColor Yellow}} catch {New-ADOrganizationalUnit -Name Computer -Path "OU=$customer_name,$domainname"}
    try {Get-ADOrganizationalUnit -Identity "OU=Terminalserver,OU=Computer,OU=$customer_name,$domainname" > $null; if ($debug -eq $True) {Write-Host "debug: OU=Terminalserver,OU=Computer,OU=$customer_name,$domainname already exists" -ForegroundColor Yellow}} catch {New-ADOrganizationalUnit -Name Terminalserver -Path "OU=Computer,OU=$customer_name,$domainname"}
    #if MP-OU Systemvariable exists change it to new OU
    if ([System.Environment]::GetEnvironmentVariable("MP-OU") -eq $null) {} 
    else {
    [System.Environment]::SetEnvironmentVariable("OU=$customer_name,$domainname",[System.EnvironmentVariableTarget]::Machine)
    }
}
#create centralstore
function create_ad_centralstore {
    if (test-path \\localhost\sysvol\$((Get-ADDomain).DNSRoot)\Policies\PolicyDefinitions) {if ($debug -eq $True) {Write-Host "debug: centralstore already exists, skipping.." -ForegroundColor Yellow}} else {copy-item C:\Windows\PolicyDefinitions \\localhost\sysvol\$((Get-ADDomain).DNSRoot)\Policies\ -Recurse}
}
#create standard ad_poicies
function create_ad_policies { 
    try {
    if ($existingGPO -like "Netzlaufwerke") {
    if ($debug -eq $True) {Write-Host "debug: gpo Netzlaufwerke already exists, creation skipped" -ForegroundColor Yellow}
    }
    else {
    New-GPO -Name Netzlaufwerke > $null
    New-GPLink -Name "Netzlaufwerke" -Target "$domainname" > $null
    }
    if ($existingGPO -like "EdgeDisableFirstRun") {
    if ($debug -eq $True) {Write-Host "debug: gpo EdgeDisableFirstRun already exists, creation skipped" -ForegroundColor Yellow}
    }
    else {
    New-GPO -Name EdgeDisableFirstRun | Out-Null > $null
    New-GPLink -Name "EdgeDisableFirstRun" -Target "$domainname" > $null
    Set-GPRegistryValue -Name 'EdgeDisableFirstRun' -Key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge' -ValueName 'hidefirstrunexperience' -Type DWord -Value 1 > $null
    Set-GPRegistryValue -Name 'EdgeDisableFirstRun' -Key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge' -ValueName 'showrecommendationsenabled' -Type DWord -Value 0 > $null
    }
    }
    catch {
    {Write-Host $(Get-Date)"[ERROR] The creation of one or more GPOs has failed. Please check Log" -ForegroundColor Red}
    }
}
#create datev share and set ACLs
function datev {
    if ($existingGroups -like "DATEVUSER") {
    Move-ADObject -Identity $((get-adgroup DATEVUSER).ObjectGUID | ForEach{$_.GUID}) -TargetPath "OU=Gruppen,OU=$customer_name,$domainname"
    if ($debug -eq $True) {Write-Host "debug: DATEVUSER already exists and is going to be moved" -ForegroundColor Yellow}
    }
    else {
    New-ADGroup -Name "DATEVUSER" -SamAccountName DATEVUSER -GroupCategory Security -GroupScope Global -DisplayName "DATEVUSER" -Path "OU=Gruppen,OU=$customer_name,$domainname"
    }
    if (Test-Path $share_drive\_FREIGABEN\WINDVSW1) {if ($debug -eq $True) {Write-Host "debug: $share_drive\_FREIGABEN\WINDVSW1 already exists" -ForegroundColor Yellow}} else {mkdir $share_drive\_FREIGABEN\WINDVSW1 > $null}
    if (Test-Path $share_drive\_FREIGABEN\WINDVSW1\CONFIGDB) {if ($debug -eq $True) {Write-Host "debug: $share_drive\_FREIGABEN\WINDVSW1\CONFIGDB already exists" -ForegroundColor Yellow}} else {mkdir $share_drive\_FREIGABEN\WINDVSW1\CONFIGDB > $null}
    #create WINDVSW1 Share
    if (Test-Path \\$env:COMPUTERNAME\WINDVSW1) {
        if ($debug -eq $True) {Write-Host "debug: Share \\$env:COMPUTERNAME\WINDVSW1 already exists" -ForegroundColor Yellow}
        }
        else {
        $DATEVShareParams = @{
        Name = "WINDVSW1"
        Path = "$share_drive\_FREIGABEN\WINDVSW1"
        ChangeAccess = "$domainnameshort\DATEVUSER"
        FullAccess = $GRPAdministrators
        }
        New-SmbShare @DATEVShareParams > $null
        }
    #set ACLs for WINDVSW1
    $DATEVACL = Get-Acl -Path "$share_drive\_FREIGABEN\WINDVSW1"
    $DATEVACL.SetAccessRuleProtection($true, $false)
    $InheritanceFlagDATEV = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $InheritanceFlag2DATEV = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit 
    $InheritanceFlag3DATEV = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlag0DATEV = [System.Security.AccessControl.PropagationFlags]::InheritOnly
    $PropagationFlag1DATEV = [System.Security.AccessControl.PropagationFlags]::None
    $SpecialRightsDATEV = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::AppendData -bor [System.Security.AccessControl.FileSystemRights]::CreateDirectories
    $DATEVAccessRule0 = New-Object System.Security.AccessControl.FileSystemAccessRule("$CREATOROWNERAccount","FullControl","$InheritanceFlagDATEV","$PropagationFlag0DATEV","Allow")
    $DATEVAccessRule1 = New-Object System.Security.AccessControl.FileSystemAccessRule("$GRPAdministrators","FullControl","$InheritanceFlagDATEV","$PropagationFlag1DATEV","Allow")
    $DATEVAccessRule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("$domainnameshort\DATEVUSER","$SpecialRightsDATEV","$InheritanceFlag3DATEV","$PropagationFlag0DATEV","Allow")
    $DATEVAccessRule3 = New-Object System.Security.AccessControl.FileSystemAccessRule("$domainnameshort\DATEVUSER","Modify","$InheritanceFlag2DATEV","$PropagationFlag1DATEV","Allow")
    $DATEVAccessRule4 = New-Object System.Security.AccessControl.FileSystemAccessRule("$SYSTEMAccount","FullControl","$InheritanceFlagDATEV","$PropagationFlag1DATEV","Allow")
    $DATEVACL.SetAccessRule($DATEVAccessRule0)
    $DATEVACL.SetAccessRule($DATEVAccessRule1)
    $DATEVACL.SetAccessRule($DATEVAccessRule2)
    $DATEVACL.AddAccessRule($DATEVAccessRule3)
    $DATEVACL.SetAccessRule($DATEVAccessRule4)
    Set-Acl -Path "$share_drive\_FREIGABEN\WINDVSW1" -AclObject $DATEVACL
}
#prepare for adconnect
function adconnect {
    if ($existingGroups -like "M365-AD-Connect") {
    if ($debug -eq $True) {Write-Host "debug: M365-AD-Connect already exists" -ForegroundColor Yellow}
    }
    else {
    New-ADGroup -Name "M365-AD-Connect" -SamAccountName M365-AD-Connect -GroupCategory Security -GroupScope Global -DisplayName "M365-AD-Connect" -Path "OU=Gruppen,OU=$customer_name,$domainname"
    }
    $wc.Downloadfile("https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi", "C:\Users\$env:USERNAME\Downloads\AzureADConnect.exe")
}
#fully configure FSLogix on DC and all Terminalservers
function fslogix {
    if (Test-Path $share_drive\_FREIGABEN\FSLogix_Container) {if ($debug -eq $True) {Write-Host "debug: $share_drive\_FREIGABEN\FSLogix_Container already exists" -ForegroundColor Yellow}} else {mkdir $share_drive\_FREIGABEN\FSLogix_Container}
    #check universial name for Everyone group and create SMB Share
    if (Test-Path \\$env:COMPUTERNAME\FSLogix_Container) {
        if ($debug -eq $True) {Write-Host "debug: Share \\$env:COMPUTERNAME\FSLogix_Container already exists" -ForegroundColor Yellow}
        }
        else {
        $everyoneSID = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
        $everyoneName = $everyoneSID.Translate([System.Security.Principal.NTAccount]).Value
        $FSLogixShareParams = @{
        Name = "FSLogix_Container"
        Path = "$share_drive\_FREIGABEN\FSLogix_Container"
        FullAccess = $everyoneName
        }
        New-SmbShare @FSLogixShareParams > $null
        }
    #set NTFS ACLs for FSLogix Share
    $FSLogixACL = Get-Acl -Path "$share_drive\_FREIGABEN\FSLogix_Container"
    $FSLogixACL.SetAccessRuleProtection($true, $false)
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlag0 = [System.Security.AccessControl.PropagationFlags]::InheritOnly
    $PropagationFlag1 = [System.Security.AccessControl.PropagationFlags]::None
    $SpecialRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::AppendData -bor [System.Security.AccessControl.FileSystemRights]::CreateDirectories 
    $FSLogixAccessRule0 = New-Object System.Security.AccessControl.FileSystemAccessRule("$CREATOROWNERAccount","FullControl","$InheritanceFlag","$PropagationFlag0","Allow")
    $FSLogixAccessRule1 = New-Object System.Security.AccessControl.FileSystemAccessRule("$GRPDomainAdmins","FullControl","$InheritanceFlag","$PropagationFlag1","Allow")
    $FSLogixAccessRule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("$GRPDomainUsers","$SpecialRights","Allow")
    $FSLogixAccessRule3 = New-Object System.Security.AccessControl.FileSystemAccessRule("$SYSTEMAccount","FullControl","$InheritanceFlag","$PropagationFlag1","Allow")
    $FSLogixACL.SetAccessRule($FSLogixAccessRule0)
    $FSLogixACL.SetAccessRule($FSLogixAccessRule1)
    $FSLogixACL.SetAccessRule($FSLogixAccessRule2)
    $FSLogixACL.SetAccessRule($FSLogixAccessRule3)
    Set-Acl -Path "$share_drive\_FREIGABEN\FSLogix_Container" -AclObject $FSLogixACL
    #download FSLogix Apps and add centralstore admx/adml
    $wc.Downloadfile("https://aka.ms/fslogix_download", "C:\Users\$env:USERNAME\Downloads\FSLogix_Apps.zip")
    Expand-Archive -LiteralPath "C:\Users\$env:USERNAME\Downloads\FSLogix_Apps.zip" -DestinationPath "C:\Users\$env:USERNAME\Downloads\FSLogix_Apps" -Force
    copy-item C:\Users\$env:USERNAME\Downloads\FSLogix_Apps\FSLogix*\fslogix.admx \\localhost\sysvol\$((Get-ADDomain).DNSRoot)\Policies\PolicyDefinitions
    copy-item C:\Users\$env:USERNAME\Downloads\FSLogix_Apps\FSLogix*\fslogix.adml \\localhost\sysvol\$((Get-ADDomain).DNSRoot)\Policies\PolicyDefinitions\de-DE
    copy-item C:\Users\$env:USERNAME\Downloads\FSLogix_Apps\FSLogix*\fslogix.adml \\localhost\sysvol\$((Get-ADDomain).DNSRoot)\Policies\PolicyDefinitions\en-US
    #Find every Terminalserver in the AD 
    $serversWithRDSWithoutADDS = Get-ADComputer -Filter {OperatingSystem -like '*server*'} | ForEach-Object {
    $server = $_.Name
    $rdsInstalled = Get-WindowsFeature -ComputerName $server -Name "Remote-Desktop-Services" | Where-Object {$_.Installed -eq $true }
    $addsInstalled = Get-WindowsFeature -ComputerName $server -Name "AD-Domain-Services" | Where-Object {$_.Installed -eq $true }
    if ($rdsInstalled -and -not $addsInstalled) {
        $server
        }
    }
    $FSLogixTERM = ""
    while(1 -ne 2)
    {
        if ($FSLogixTERM -eq "y") {write-host "Setup is continued as planned";break} 
        if ($FSLogixTERM -eq "n") {write-host "FSLogix Install on Terminalserver skipped. Maual install necessary";$serversWithRDSWithoutADDS = $null;break}
        else {$FSLogixTERM = Read-Host "The following Terminalservers where found: $serversWithRDSWithoutADDS is that correct? [y/n]"}
    }
    #Install FSLogix on every Terminalserver and add domainadmins to exclude group. And move TS to OU
    ForEach ($RDS in $serversWithRDSWithoutADDS) {
        $RDS_DN = (Get-ADObject -Filter "Name -eq '$RDS'").DistinguishedName
        Move-ADObject -Identity "$RDS_DN" -TargetPath "OU=Terminalserver,OU=Computer,OU=$customer_name,$domainname"
        Invoke-Command -ComputerName $RDS -ScriptBlock {
        Write-Host $(Get-Date)"[INFO] FSLogix is being installed on $Using:RDS"
        $wc = New-Object net.webclient
        $wc.Downloadfile("https://aka.ms/fslogix_download", "C:\Users\$env:USERNAME\Downloads\FSLogix_Apps.zip")
        Expand-Archive -LiteralPath "C:\Users\$env:USERNAME\Downloads\FSLogix_Apps.zip" -DestinationPath "C:\Users\$env:USERNAME\Downloads\FSLogix_Apps" -Force
        Set-Location "C:\Users\$env:USERNAME\Downloads\FSLogix_Apps\*\x64\Release\"
        $fsxinst = (get-childitem).name
        if ($debug -eq $True) {Write-Host "debug: $fsxinst successfully downloaded and extracted in C:\Users\$env:USERNAME\Downloads\FSLogix_Apps on $RDS" -ForegroundColor Yellow} 
        ForEach ($prog in $fsxinst) {
            cmd /c $prog /install /quiet
            start-sleep 5
            }
        if ((Get-LocalGroupMember -Name "FSLogix Profile Exclude List").Name -like "*$Using:GRPDomainAdmins") {
            Write-Host $(Get-Date)"[INFO] $Using:GRPDomainAdmins already exists in local group FSLogix Profile Exclude List on $Using:RDS"
            }
            else {
            Add-LocalGroupMember -Group "FSLogix Profile Exclude List" -Member "$Using:GRPDomainAdmins"
            }
            gpupdate > $null
        }
    }
    #add FSLogix GPOs
    function $Set-FSLogixGPO {
    New-GPO -Name FSLogix
    New-GPLink -Name "FSLogix" -Target "OU=Terminalserver,OU=Computer,OU=$customer_name,$domainname"
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Logging' -ValueName 'LogFileKeepingPeriod' -Type DWord -Value 7 > $null
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'Enabled' -Type DWord -Value 1 > $null
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'IsDynamic' -Type DWord -Value 1 > $null
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'ProfileType' -Type DWord -Value 3 > $null
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'SizeInMBs' -Type DWord -Value 30000 > $null
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'VHDLocations' -Type String -Value "\\$([System.Net.Dns]::GetHostByName($env:computerName).HostName)\FSLogix_Container" > $null
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'LockedRetryCount' -Type DWord -Value 12 > $null
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'VolumeType' -Type String -Value VHDX > $null
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'FlipFlopProfileDirectoryName' -Type DWord -Value 1 > $null
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'PreventLoginWithFailure' -Type DWord -Value 1 > $null
    Set-GPRegistryValue -Name 'FSLogix' -Key 'HKEY_LOCAL_MACHINE\Software\fslogix\Profiles' -ValueName 'DeleteLocalProfileWhenVHDShouldApply' -Type DWord -Value 1 > $null
    }
    try {
    if ($existingGPO -like "FSLogix") {
    $FSLogixGPO = ""
    while(1 -ne 2)
    {
        if ($FSLogixGPO -eq "y") {write-host "Overwriting..";Remove-GPO FSLogix;Set-FSLogixGPO;break} 
        if ($FSLogixGPO -eq "n") {write-host "Skipping FSLogix GPO creation, manual work may be necessary";break}
        else {$FSLogixGPO = Read-Host "FSLogix GPO already exists. Do you want to overwrite it? [y/n]"}
    }
    }
    else {
    Set-FSLogixGPO
    }
    }
    catch {
    Write-Host $(Get-Date)"[ERROR] FSLogix Group Policy creation failed! please check and possibly recreate this GPO" -ForegroundColor Red; $global:errorcount ++
    }
}

#check if successfull
function check {
    if ((Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"').EnabledScopes) {Write-Host $(Get-Date)"[INFO] Active Directory Recycle Bin successfully activated"} else {Write-Host $(Get-Date)"[ERROR] Active Directory Recycle Bin was not activated" -ForegroundColor Red; $global:errorcount ++}
    if([adsi]::Exists("LDAP://OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[INFO] OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] OU=$customer_name,$domainname creation failed" -ForegroundColor Red; $global:errorcount ++}
    if([adsi]::Exists("LDAP://OU=Benutzer,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[INFO] OU=Benutzer,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] OU=Benutzer,OU=$customer_name,$domainname creation failed" -ForegroundColor Red; $global:errorcount ++}
    if([adsi]::Exists("LDAP://OU=Gruppen,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[INFO] OU=Gruppen,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] OU=Gruppen,OU=$customer_name,$domainname creation failed" -ForegroundColor Red; $global:errorcount ++}
    if([adsi]::Exists("LDAP://OU=Computer,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[INFO] OU=Computer,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] OU=Computer,OU=$customer_name,$domainname creation failed" -ForegroundColor Red; $global:errorcount ++}
    if([adsi]::Exists("LDAP://OU=Terminalserver,OU=Computer,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[INFO] OU=Terminalserver,OU=Computer,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] OU=Terminalserver,OU=Computer,OU=$customer_name,$domainname creation failed" -ForegroundColor Red; $global:errorcount ++}
    if ([System.Environment]::GetEnvironmentVariable("MP-OUs") -eq $null) {} else {if ([System.Environment]::GetEnvironmentVariable("MP-OU") -eq "OU=$customer_name,$domainname") {Write-Host $(Get-Date)"[INFO] Systemvariable MP-OU successfully set to OU=$customer_name,$domainname"} else {Write-Host $(Get-Date)"[ERROR] setting Systemvariable MP-OU to OU=$customer_name,$domainname failed" -ForegroundColor Red; $global:errorcount ++}}
    if ($datev -eq "y") { if([adsi]::Exists("LDAP://CN=DATEVUSER,OU=Gruppen,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[INFO] CN=DATEVUSER,OU=Gruppen,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] CN=DATEVUSER,OU=Gruppen,OU=$customer_name,$domainname creation failed" -ForegroundColor Red; $global:errorcount ++}}
    if ($datev -eq "y") { if(test-path $share_drive\_FREIGABEN\WINDVSW1\CONFIGDB) {Write-Host $(Get-Date)"[INFO] Folder $share_drive\_FREIGABEN\WINDVSW1\CONFIGDB successfully created"} else {Write-Host $(Get-Date)"Folder creation failed" -ForegroundColor Red; $global:errorcount ++}}
    if ($adconnect -eq "y") { if([adsi]::Exists("LDAP://CN=M365-AD-Connect,OU=Gruppen,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[INFO] CN=M365-AD-Connect,OU=Gruppen,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] CN=M365-AD-Connect,OU=Gruppen,OU=$customer_name,$domainname creation failed" -ForegroundColor Red; $global:errorcount ++}}
    if ((Get-GPO -Name Netzlaufwerke) -ne "" ) {Write-Host $(Get-Date)"[INFO] GPO Netzlaufwerke successfully created"} else {Write-Host $(Get-Date)"[ERROR] GPO Netzlaufwerke creation failed" -ForegroundColor Red; $global:errorcount ++}
    if ((Get-GPO -Name EdgeDisableFirstRun) -ne "" ) {Write-Host $(Get-Date)"[INFO] GPO EdgeDisableFirstRun successfully created"} else {Write-Host $(Get-Date)"[ERROR] GPO EdgeDisableFirstRun creation failed" -ForegroundColor Red; $global:errorcount ++}
    if (test-path \\localhost\sysvol\$((Get-ADDomain).DNSRoot)\Policies\PolicyDefinitions) {Write-Host $(Get-Date)"[INFO] centralstore successfully created"} else {Write-Host $(Get-Date)"[INFO] centralstore successfully failed" -ForegroundColor Red; $global:errorcount ++}
    if ($global:errorcount -eq $null) {
        Write-Host $(Get-Date)"[INFO] The Script encountered no errors." -ForegroundColor Green
    }
    else {
        Write-Host $(Get-Date)"[ERROR] The Script encountered $global:errorcount errors. Please check the Log" -ForegroundColor Red
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
