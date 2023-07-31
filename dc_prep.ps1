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
    Write-Host $(Get-Date)"[INFO]Configfile found. Configuration is read from file"
    $customer_name = (Get-Content $configfilepath -TotalCount 1).Substring(16)
    $datev = (Get-Content $configfilepath -TotalCount 1).Substring(16)
} 
else {
    Write-Host $(Get-Date)"[INFO]No configfile found. Parameters have to be defined manually"
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
        if ($adconnect -eq "y") {write-host "Azuer-AD-Connect is going to be configured";break} 
        if ($adconnect -eq "n") {write-host "Azuer-AD-Connect is NOT going to be configured";break}
        else {$adconnect = Read-Host "Configure Azure-AD-Connect? [y/n]"}
    }
}

function create_ad_ou {
    New-ADOrganizationalUnit -Name $customer_name -Path $domainname
    New-ADOrganizationalUnit -Name Benutzer -Path "OU=$customer_name,$domainname"
    New-ADOrganizationalUnit -Name Gruppen -Path "OU=$customer_name,$domainname"
    New-ADOrganizationalUnit -Name Terminalserver -Path "OU=$customer_name,$domainname"
}

function create_ad_groups { 
    
}

function datev {
    New-ADGroup -Name "DATEVUSER" -SamAccountName DATEVUSER -GroupCategory Security -GroupScope Global -DisplayName "DATEVUSER" -Path "OU=Gruppen,OU=$customer_name,$domainname"
    $wc.Downloadfile("https://download.datev.de/download/datevitfix/serverprep.exe", "C:\Users\$env:USERNAME\Downloads\serverprep.exe")

}

function adconnect {
    New-ADGroup -Name "M365-AD-Connect" -SamAccountName M365-AD-Connect -GroupCategory Security -GroupScope Global -DisplayName "M365-AD-Connect" -Path "OU=Gruppen,OU=$customer_name,$domainname"
    $wc.Downloadfile("https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi", "C:\Users\$env:USERNAME\Downloads\AzureADConnect.exe")
}

#check if successfull
function check {
    $exitcode = 0
    if([adsi]::Exists("LDAP://OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] OU=$customer_name,$domainname creation failed"; $exitcode +1}
    if([adsi]::Exists("LDAP://OU=Benutzer,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] OU=Benutzer,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] OU=Benutzer,OU=$customer_name,$domainname creation failed"; $exitcode +1}
    if([adsi]::Exists("LDAP://OU=Gruppen,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] OU=Gruppen,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] OU=Gruppen,OU=$customer_name,$domainname creation failed"; $exitcode +1}
    if([adsi]::Exists("LDAP://OU=Terminalserver,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] OU=Terminalserver,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] OU=Terminalserver,OU=$customer_name,$domainname creation failed"; $exitcode +1}
    if ($datev -eq "y") { if([adsi]::Exists("LDAP://CN=DATEVUSER,OU=Gruppen,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] CN=DATEVUSER,OU=Gruppen,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] CN=DATEVUSER,OU=Gruppen,OU=$customer_name,$domainname creation failed"; $exitcode +1}}
    if ($adconnect -eq "y") { if([adsi]::Exists("LDAP://CN=M365-AD-Connect,OU=Gruppen,OU=$customer_name,$domainname")) {Write-Host $(Get-Date)"[Info] CN=M365-AD-Connect,OU=Gruppen,OU=$customer_name,$domainname successfully created"} else {Write-Host $(Get-Date)"[ERROR] CN=M365-AD-Connect,OU=Gruppen,OU=$customer_name,$domainname creation failed"; $exitcode +1}}

    if ($exitcode -eq 0) {
        Write-Host $(Get-Date)"[INFO]The Script encountered no errors."
    }
    else {
        Write-Host $(Get-Date)"[ERROR]The Script encountered $exitcode errors. Please check the Log" -ForegroundColor Red
    }
}

#run script as specified
create_ad_ou
create_ad_groups
if ($datev -eq "y") {datev}
if ($adconnect -eq "y") {adconnect}
check
