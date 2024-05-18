<#
    v1.2 CHANGELOG (Kyle Smith):
    - Added -AllowClobber to Import-PSSession to get rid of error message
    - Changed Read-Host statements to Param()
    - Changed:
        $acl.Access | %{$acl.RemoveAccessRule($_)}
      To:
        $acl.Access | ForEach-Object{$acl.RemoveAccessRule($_)}
    - Changed:
        if($User -ne $null) {
      To:
        if($Null -ne $User) {
    - Added help message if -h is passed
#>

# Prompt for data
Param (
    [switch]$h, 

    [Parameter(Mandatory=$False, Position=1)]
    [ValidateNotNullOrEmpty()]
    [string]$first,

    [Parameter(Mandatory=$False, Position=2)]
    [ValidateNotNullOrEmpty()]
    [string]$last,

    [Parameter(Mandatory=$False, Position=3)]
    [ValidateNotNullOrEmpty()]
    [string]$jobtitle,

    [Parameter(Mandatory=$False, Position=4)]
    [ValidateNotNullOrEmpty()]
    [string]$department,

    [Parameter(Mandatory=$False, Position=5)]
    [ValidateNotNullOrEmpty()]
    [string]$manager,

    [Parameter(Mandatory=$False, Position=6)]
    [ValidateNotNullOrEmpty()]
    [string]$phonenumber
)

if ($h) 
{
    Write-Host ""
    Write-Host "Usage: .\NewOfficeUser-v1.2.ps1 <firstname> <lastname> <jobtitle> <department> <manager> <phonenumber>"
    Write-Host ""
    Write-Host "NOTE: Manager username should be Email prefix only Ex: ks"
    Write-Host "NOTE: Phone number should be seperated by dashes Ex: 555-555-5555"
    Write-Host ""
    exit
}

$company = "VersaLife, Inc."
$loginid = ($first.SubString(0,1)).ToLower() + $last.ToLower()
$upn = "$loginid@helios.net"

# Make Connection to Exchange
$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://auth.helios.net/kerberos/ -Authentication Kerberos
Import-PSSession $session -AllowClobber
New-RemoteMailbox -Name "$first $last" -DisplayName "$first $last" -UserPrincipalName $upn -Password (ConvertTo-SecureString -String '' -AsPlainText -Force) -FirstName $first -LastName $last -SamAccountName $loginid
# NOTICE: Change password every calendar year.

# Set Job Title, Department, Company Name, Manager, Phone Number
Set-ADUser -Identity $loginid -Manager $manager -Company $company -OfficePhone $phonenumber -Department $department -Title $jobtitle
Add-ADGroupMember -Identity "group0" -Members $loginid
Add-ADGroupMember -Identity "group1" -Members $loginid
Add-MailboxPermission -Identity "$loginid" -user "Exchange Admin" -AccessRights FullAccess -InheritanceType All


# Force Azure AD Connect Sync Job
Invoke-Command -ComputerName DomainController -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}
Send-MailMessage -To "$loginid@helios.net" -From "Administrator@helios.net" -Subject "Change Your Password" -body "Its a bad one. You should change it." -smtpserver "mail.helios.net"
Remove-PSSession $session

# Start File Permission Work
$fullPath = "\\home\users\{0}" -f $loginid
$driveLetter = "C:"
 
$User = Get-ADUser -Identity $loginid
 
if ($Null -ne $User) 
{
    Set-ADUser $User -HomeDrive $driveLetter -HomeDirectory $fullPath -ea Stop
    $homeShare = New-Item -path $fullPath -ItemType Directory -force -ea Stop
 
    $acl = Get-Acl $homeShare
 
    $FileSystemRights = [System.Security.AccessControl.FileSystemRights]"Modify"
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $PropagationFlags = [System.Security.AccessControl.PropagationFlags]"InheritOnly"
 
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($User.SID, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)
    $acl.AddAccessRule($AccessRule)
 
    Set-Acl -Path $homeShare -AclObject $acl -ea Stop
 
    Write-Host ("User home created at {0}" -f $fullPath)
} 

$acl = Get-Acl $fullPath
$acl.SetAccessRuleProtection($True, $False)
$acl.Access | ForEach-Object{$acl.RemoveAccessRule($_)}
$acl.SetOwner([System.Security.Principal.NTAccount] $loginid)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($loginid,'Modify','ContainerInherit,ObjectInherit','None','Allow')
$rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule('Admins','FullControl','ContainerInherit,ObjectInherit','None','Allow')

$acl.AddAccessRule($rule)
$acl.AddAccessRule($rule2)
Set-Acl $FullPath $acl | Out-Null
New-Item $fullpath\Documents -ItemType Directory
New-Item $fullpath\Pictures -ItemType Directory
