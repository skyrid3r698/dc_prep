# dc_prep

## Running the Script

    1. Configure the configfile dc_prep.conf as needed

    customer_name: Customer name which is used as the first OU in the Active Directory
    datev,adconnect,FSLogix: set y or n. With y the specified funktion is being run. With n it is being skipped
    sharedrive: specifies the physical drive on which the Files for Datev and FSLogix are being saved and shared. Syntax is DriveLetter:
    2. Open Powershell on domaincontroller as domain-administrator
    3. Set-Executionpolicy 0
    4. navigate to the scriptfolder and run dc_prep.ps1
    5. Check for errors

## Parameter

    ### debug
        There is a parameter "-debug". This parameter shows alot more information when running the script.

## Features

    Default
        activates the ActiveDirectory RecycleBin
        creates a folder "_FREIGABEN" in the specified Path for "sharedrive"
        creates multiple OUs for better structure: customer_name -> Benutzer, Gruppen, Computer -> Terminalserver
        If Microplan Datacenter is being found, the needed enviroment variable is being set
        the centralstore ist being activated and configured
        The following Grouppolicies are being created: Netzlaufwerke (empty, linked to domain), EdgeDisableFirstRun (deactivates Edge first run Setuo, linked to domain),
        default computer and user OU is being changed to newly created one
    if datev: y
        If DATEVUSER Group already exists it it being moved to newly created OU "Gruppen". If it does not exists it is being created
        $sharedrive\_FREIGABEN\WINDVSW1 and Subfolder CONFIGD is being created
        NTFS-Rights and Share-Rights are being set for WINDVSW1 with DATEV specifications
        WINDVSW1 is being shared
    if adconnect: y
        The Group M365-AD-Connect is bein created under OU "Gruppen"
        AzureADConnect.exe is being created
    if FSLogix: y
        $sharedrive\_FREIGABEN\FSLogix_Container is being created
        NTFS-Rights und Share-Rights are being set for FSLogix_Container with Microsoft specifications
        The folder FSLogix_Container is being shared
        The AD is being searched for all Terminalservers and istalls FSLogix on every one of them and adds domain-admins group to local FSLogix-Exclude Group after user confirms the found ones
        moves all found Terminalservers to newly created OU "Terminalserver"
        adds FSLogix.adml and admx to the centralstore
        Creates and preconfigures the FSLogix GPO and links them to Terminalserver OU
        → FSLogix is fully configured after this and can be used immidiently
    if UserList: y
        AD-Users are being created as provided in the csv-List
        The AD-Suffix from the emailaddress is being created if it does not already exist
