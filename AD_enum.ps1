# version 22.11.24

# Define the executable name
$exeName = "./adsearch.exe"
$computerName = $env:COMPUTERNAME

# Define arrays for parameters and descriptions
$exeDesc = @(
    'All domain controllers',
    'Domain Controllers 2',
    'all objects whose category is User',
    'all users v2 from SharpSpray',
    'all domain groups which end in the word "admins"',
    'Domain Admins',
    'domain users who have an SPN set',
    'LAPS password 1',
    'LAPS password 2',
    'all computers that are permitted for unconstrained delegation',
    'ASREP Roasting, does not have Kerberos pre-authentication enabled',
    'find computers configured for constrained delegation (also need USERS)',
    'find Users configured for constrained delegation (also need USERS)',
    'Kerberoasting 1',
    'Kerberoasting 2',
    'Kerberoasting 3',
    'Accounts Trusted for Delegation',
    'All users (more effective)',
    'All users',
    'All users with the account configuration - Password never expires',
    'All GPOs',
    'Attributes with passwords',
    'Certificates',
    'All Security Groups',
    'All groups',
    'Terminal Servers',
    'MSSQL Servers'
)

$exeParam = @(
    '--search "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"',
    '--search "(&(objectclass=computer)(name=DC))"',
    '--search "objectCategory=user"',
    '--search "(&(objectCategory=Person)(sAMAccountName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"',
    '--search "(&(objectCategory=group)(cn=*Admins))"',
    '--search "(&(objectclass=group)(samaccountname=domain admins))"',
    '--search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes cn,servicePrincipalName,samAccountName',
    '--search "(ms-MCS-AdmPwd=*)"',
    '--search "(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=" + $computerName + "))"',
    '--search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname',
    '--search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname',
    '--search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json',
    '--search "(&(objectCategory=user)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json',
    '--search "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))"',
    '--search "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24))"',
    '--search "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24))"',
    '--search "(userAccountControl:1.2.840.113556.1.4.803:=524288)"',
    '--search "(sAMAccountType=805306368)"',
    '--search "(&(objectCategory=person)(objectClass=user))"',
    '--search "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)"',
    '--search "(objectClass=groupPolicyContainer)"',
    '--search "(|(userpassword=*)(ms-msc-admpwd=*)(unicodePwd=*)(unixUserPassword=*)(msSFU30Password=*)(os400Password=*))"',
    '--search "(|(objectCategory=pKIEnrollmentService)(objectCategory=certificationAuthority))"',
    '--search "(groupType:1.2.840.113556.1.4.803:=2147483648)"',
    '--search "(objectClass=group)"',
    '--search "(&(objectClass=computer)(memberOf=CN=Terminal Server License Servers,CN=Users,CN=Builtin,DC=domain,DC=local))"',
    '--search "(&(objectClass=computer)(servicePrincipalName=*MSSQLSvc/*))"'
    
    
)

# Function to display the operation description and launch the executable
function LaunchExe {
    param (
        [int]$index
    )
    # Clean up previous output files
    Remove-Item output.txt -ErrorAction SilentlyContinue
    Remove-Item error.txt -ErrorAction SilentlyContinue
    $timeoutInSeconds = 10
    
    Write-Host "Operation: $($exeDesc[$index]). And the filter: $($exeParam[$index]) "
# Create the argument list
    $argumentList = @($exeName)
    $argumentList += $exeParam[$index].Split(" ")

# Use Start-Process to launch the executable and capture output
    $process = Start-Process -FilePath $exeName -ArgumentList $argumentList -NoNewWindow -RedirectStandardOutput output.txt -RedirectStandardError error.txt -PassThru -Wait

 # Wait for the process to exit or timeout
    $process | Wait-Process -Timeout $timeoutInSeconds

    # Check if the process is still running after the timeout
    if (!$process.HasExited) {
        # If it hasn't exited, kill the process
        Write-Host "Timeout exceeded for parameter '$param'. Terminating process."
        Stop-Process -Id $process.Id -Force
    } else {
        Write-Host "Process completed successfully"
    }

# Read the output and error files
    if (Test-Path output.txt) {
        $output = Get-Content output.txt | Out-String
        Write-Host "Command output:"
        Write-Host $output
    }

    if (Test-Path error.txt) {
        $errorOutput = Get-Content error.txt | Out-String
        if ($errorOutput) {
            Write-Host "Command error output:"
            Write-Host $errorOutput
        }
    }

    # Clean up previous output files
    Remove-Item output.txt -ErrorAction SilentlyContinue
    Remove-Item error.txt -ErrorAction SilentlyContinue

}

# Main script execution
Write-Host "This PowerShell script will perform the following operations:"
Write-Host

# Loop through the arrays to launch the executable with different parameters
for ($i = 0; $i -lt $exeDesc.Length; $i++) {
    LaunchExe -index $i
    Write-Host
}

Write-Host "End of the PowerShell script."
