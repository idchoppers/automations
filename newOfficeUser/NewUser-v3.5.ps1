<#
    NewUser-v3.5.ps1

    Description:

    In human speak:
    This script creates a new Active Directory user given the information inputted in the GUI.
    The information is case sensitive, if there are any mistakes then the program will not catch them!
    For the "Manager Username" field, input the first part of the email address of the manager. Ex:
    ks NOT ks@helios.net

    In programmer speak (pseudo-code):
    Create Active Directory user named (first, last) of type [default, grp0, grp1, grp2] with data (title, dept, manager, phone#)
    If user is of type (default, grp0, grp1, grp2)
        Assign appropriate permissions
        Change password to a temporary password
        Create a Home Directory at \\home\user\(user)
    
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

v3.5 CHANGELOG (Kyle Smith):
    - Added function for grp3 user
    - To add a grp3 user you change their SMTP proxy address and add them to the grp3 groups
    - Added grp3 checkbox to GUI, removed status bar on GUI, it has been replaced with the status on the PowerShell prompt
    - Minor bug fixes

v3.0 CHANGELOG (Kyle Smith):
    - Console window title now acts as a status
    - Added status messages in console
    - Added descriptions
    - Made minor GUI changes
    - Switched from if/else statement to switch/case to handle selecting the user type because it is easier to read
    - Merging the grp0, grp1, and grp2 scripts into this one, the plan is to seperate each into respective functions that will be called given interaction on the GUI
    - Added and modified the scripts into respective functions (NewGRP0User, NewGRP1User, NewGRP2User) and made a function for the default user script (NewDefaultUser)
    - Added new GUI elements to the XAML window

v2.0 CHANGELOG (Kyle Smith):
    - Added SendAs permission from user's mailbox to Administrator
    - Removed all logic for Param() due to GUI logic
    - Added a GUI

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

$host.ui.RawUI.WindowTitle = "New User v3.5 - Status"

function NewDefaultUser() {
    $host.ui.RawUI.WindowTitle = "New User v3.5 - Working..."

    # Make Connection to Exchange
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://auth.helios.net/kerberos/ -Authentication Kerberos
    Import-PSSession $session -AllowClobber
    New-RemoteMailbox -Name "$($var_first.Text) $($var_last.Text)" -DisplayName "$($var_first.Text) $($var_last.Text)" -UserPrincipalName $upn -Password (ConvertTo-SecureString -String $password -AsPlainText -Force) -FirstName $var_first.Text -LastName $var_last.Text -SamAccountName $loginid -DomainController DC2.Keystone.local
    # NOTICE: Change password every calendar year.

    # Set Job Title, Department, Company Name, Manager, Phone Number
    Set-ADUser -Identity $loginid -Manager $var_manager.Text -Company $company -OfficePhone $var_phonenumber.Text -Department $var_department.Text -Title $var_jobtitle.Text
    Add-ADGroupMember -Identity "group0" -Members $loginid
    Add-ADGroupMember -Identity "group1" -Members $loginid

    # Add permissions
    Add-MailboxPermission -Identity "$loginid" -user "Administrator" -AccessRights FullAccess -InheritanceType All
    Add-MailboxPermission $upn -AccessRights SendAs -User "Administrator"

    # Force Azure AD Connect Sync Job
    Invoke-Command -ComputerName DomainController -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}
    Send-MailMessage -To "$loginid@helios.net" -From "Administrator@helios.net" -Subject "Change your password" -body "Change now." -smtpserver "mail.helios.net"
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
    $rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule('Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow')

    $acl.AddAccessRule($rule)
    $acl.AddAccessRule($rule2)
    Set-Acl $FullPath $acl | Out-Null
    New-Item $fullpath\Documents -ItemType Directory
    New-Item $fullpath\Pictures -ItemType Directory

    $host.ui.RawUI.WindowTitle = "New User v3.5 - Done!"
    Write-Host "Done making User!" -ForegroundColor Green
}

function NewGRP3User() {
    $host.ui.RawUI.WindowTitle = "New User v3.5 - Working..."

    # Make Connection to Exchange
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://auth.helios.net/kerberos/ -Authentication Kerberos
    Import-PSSession $session -AllowClobber
    New-RemoteMailbox -Name "$($var_first.Text) $($var_last.Text)" -DisplayName "$($var_first.Text) $($var_last.Text)" -UserPrincipalName $upn -Password (ConvertTo-SecureString -String $password -AsPlainText -Force) -FirstName $var_first.Text -LastName $var_last.Text -SamAccountName $loginid -DomainController DC2.Keystone.local
    # NOTICE: Change password every calendar year.

    # Set Job Title, Department, Company Name, Manager, Phone Number
    Set-ADUser -Identity $loginid -Manager $var_manager.Text -Company $company -OfficePhone $var_phonenumber.Text -Department $var_department.Text -Title $var_jobtitle.Text
    Add-ADGroupMember -Identity "group1" -Members $loginid
    Add-ADGroupMember -Identity "group0" -Members $loginid
    Add-ADGroupMember -Identity "grp3" -Members $loginid
    Add-ADGroupMember -Identity "GRP3" -Members $loginid

    # Change SMTP proxy address to Penn Transfer address
    Import-Module ActiveDirectory -DisableNameChecking
    $User = Get-ADUser $loginid -Properties proxyAddresses
    $User.proxyAddresses.Remove("SMTP:$loginid@helios.net")
    $User.proxyAddresses.Add("smtp:$loginid@helios.net")
    $User.proxyAddresses.Add("SMTP:$loginid@icarus.net")
    Set-ADUser -instance $User

    # Add permissions
    Add-MailboxPermission -Identity "$loginid" -user "Administrator" -AccessRights FullAccess -InheritanceType All
    Add-MailboxPermission $upn -AccessRights SendAs -User "Administrator"

    # Force Azure AD Connect Sync Job
    Invoke-Command -ComputerName DomainController -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}
    Send-MailMessage -To "$loginid@helios.net" -From "Administrator@helios.net" -Subject "Change your password" -body "Change now." -smtpserver "mail.helios.net"
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
    $rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule('Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow')

    $acl.AddAccessRule($rule)
    $acl.AddAccessRule($rule2)
    Set-Acl $FullPath $acl | Out-Null
    New-Item $fullpath\Documents -ItemType Directory
    New-Item $fullpath\Pictures -ItemType Directory

    $host.ui.RawUI.WindowTitle = "New User v3.5 - Done!"
    Write-Host "Done making User!" -ForegroundColor Green
}

function NewGRP0User() {
    $host.ui.RawUI.WindowTitle = "New User v3.5 - Working..."

    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://auth.helios.net/kerberos/ -Authentication Kerberos
    Import-PSSession $session
    New-RemoteMailbox -Name "$($var_first.Text) $($var_last.Text)" -DisplayName "$($var_first.Text) $($var_last.Text)" -UserPrincipalName $upn -Password (ConvertTo-SecureString -String $password -AsPlainText -Force) -FirstName $var_first.Text -LastName $var_last.Text -SamAccountName $loginid -DomainController DC2.Keystone.local
    
    
    Add-ADGroupMember -Identity "group1" -Members $loginid
    
    Add-ADGroupMember -Identity "group0" -Members $loginid
    
    Add-MailboxPermission -Identity "$loginid" -user "Administrator" -AccessRights FullAccess -InheritanceType All
    
    
    #Force Azure AD Connect Sync Job
    Invoke-Command -ComputerName DomainController -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}
    
    Send-MailMessage -To "$loginid@helios.net" -From "Administrator@helios.net" -Subject "Change your password" -body "Change now." -smtpserver "mail.helios.net"
    
    Remove-PSSession $session
    
    #Start File Permission Work
    
    $fullPath = "\\home\users\{0}" -f $loginid
    $driveLetter = "C:"
     
    $User = Get-ADUser -Identity $loginid
     
    if($Null -ne $User) {
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
    $acl.Access | ForEach-Object{$acl.RemoveAccessRule($_)} # I remove all security
    $acl.SetOwner([System.Security.Principal.NTAccount] $loginid) # I set the current user as owner
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($loginid,'Modify','ContainerInherit,ObjectInherit','None','Allow')
    $rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule('Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow')
    
    $acl.AddAccessRule($rule)
    $acl.AddAccessRule($rule2)
    Set-Acl $FullPath $acl | Out-Null
    New-Item $fullpath\Documents -ItemType Directory
    New-Item $fullpath\Pictures -ItemType Directory

    $host.ui.RawUI.WindowTitle = "New User v3.5 - Done!"
    Write-Host "Done making GRP0!" -ForegroundColor Green
}

function NewGRP1User() {
    $host.ui.RawUI.WindowTitle = "New User v3.5 - Working..."

    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://auth.helios.net/kerberos/ -Authentication Kerberos
    Import-PSSession $session
    New-RemoteMailbox -Name "$($var_first.Text) $($var_last.Text)" -DisplayName "$($var_first.Text) $($var_last.Text)" -UserPrincipalName $upn -Password (ConvertTo-SecureString -String $password -AsPlainText -Force) -FirstName $var_first.Text -LastName $var_last.Text -SamAccountName $loginid -DomainController DC2.Keystone.local


    Add-ADGroupMember -Identity "grp1" -Members $loginid

    Add-MailboxPermission -Identity "$loginid" -user "Administrator" -AccessRights FullAccess -InheritanceType All

    Remove-PSSession $session

    #Force Azure AD Connect Sync Job
    Invoke-Command -ComputerName DomainController -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}

    Send-MailMessage -To "$loginid@helios.net" -From "Administrator@helios.net" -Subject "Change your password" -body "Change now." -smtpserver "mail.helios.net"

    $host.ui.RawUI.WindowTitle = "New User v3.5 - Done!"
    Write-Host "Done making GRP1!" -ForegroundColor Green
}

function NewGRP2User() {
    $host.ui.RawUI.WindowTitle = "New User v3.5 - Working..."

    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://auth.helios.net/kerberos/ -Authentication Kerberos
    Import-PSSession $session
    New-RemoteMailbox -Name "$($var_first.Text) $($var_last.Text)" -DisplayName "$($var_first.Text) $($var_last.Text)" -UserPrincipalName $upn -Password (ConvertTo-SecureString -String $password -AsPlainText -Force) -FirstName $var_first.Text -LastName $var_last.Text -SamAccountName $loginid -DomainController DC2.Keystone.local


    Add-ADGroupMember -Identity "grp2" -Members $loginid

    Add-ADGroupMember -Identity "group0" -Members $loginid

    Add-MailboxPermission -Identity "$loginid" -user "Administrator" -AccessRights FullAccess -InheritanceType All

    #Force Azure AD Connect Sync Job
    Invoke-Command -ComputerName DomainController -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}

    Send-MailMessage -To "$loginid@helios.net" -From "Administrator@helios.net" -Subject "Change your password" -body "Change now." -smtpserver "mail.helios.net"

    Remove-PSSession $session

    #Start File Permission Work

    $fullPath = "\\home\users\{0}" -f $loginid
    $driveLetter = "C:"
    
    $User = Get-ADUser -Identity $loginid
    
    if($Null -ne $User) {
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
    $acl.Access | ForEach-Object{$acl.RemoveAccessRule($_)} # I remove all security
    $acl.SetOwner([System.Security.Principal.NTAccount] $loginid) # I set the current user as owner
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($loginid,'Modify','ContainerInherit,ObjectInherit','None','Allow')
    $rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule('Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow')

    $acl.AddAccessRule($rule)
    $acl.AddAccessRule($rule2)
    Set-Acl $FullPath $acl | Out-Null
    New-Item $fullpath\Documents -ItemType Directory
    New-Item $fullpath\Pictures -ItemType Directory

    $host.ui.RawUI.WindowTitle = "New User v3.5 - Done!"
    Write-Host "Done making GRP2!" -ForegroundColor Green
}

Add-Type -AssemblyName PresentationFramework

# Points to XAML file that defines the GUI
$xamlFile = ".\MainWindow3.5.xaml"

# create window
$inputXML = Get-Content $xamlFile -Raw
$inputXML = $inputXML -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window'
[XML]$XAML = $inputXML

# Read XAML
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
try {
    $window = [Windows.Markup.XamlReader]::Load( $reader )
} catch {
    Write-Warning $_.Exception
    throw
}

# Create variables based on form control names.
# Variable will be named as 'var_<control name>'
$xaml.SelectNodes("//*[@Name]") | ForEach-Object {
    # "trying item $($_.Name)"
    try {
        Set-Variable -Name "var_$($_.Name)" -Value $window.FindName($_.Name) -ErrorAction Stop
    } catch {
        throw
    }
}

$var_btnCreate.Add_Click({
    # If your editor of choice complains about these variables not being used, then it is lying to you and probably has ulterior motives
    $password = ""
    $company = "VersaLife, Inc."
    $loginid = ($var_first.Text.SubString(0,1)).ToLower() + $var_last.Text.ToLower()
    $upn = "$loginid@helios.net"

    switch ($true) {
        $var_grp0.IsChecked { NewGRP0User; break }
        $var_grp1.IsChecked { NewGRP1User; break }
        $var_grp2.IsChecked { NewGRP2User; break }
        $var_grp3.IsChecked { NewGRP3User; break}
        Default { NewDefaultUser; break }
    }
})

$Null = $window.ShowDialog()
