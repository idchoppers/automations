<#
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

Add-Type -AssemblyName PresentationFramework

# Points to XAML file that defines the GUI
$xamlFile = ".\MainWindow.xaml"

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

$var_btnCreate.Add_Click( {
    $var_status.Text = " "
    
    $company = "VersaLife, Inc."
    $loginid = ($var_first.Text.SubString(0,1)).ToLower() + $var_last.Text.ToLower()
    $upn = "$loginid@helios.net"

    # Make Connection to Exchange
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://auth.helios.net/kerberos/ -Authentication Kerberos
    Import-PSSession $session -AllowClobber
    New-RemoteMailbox -Name "$($var_first.Text) $($var_last.Text)" -DisplayName "$($var_first.Text) $($var_last.Text)" -UserPrincipalName $upn -Password (ConvertTo-SecureString -String '' -AsPlainText -Force) -FirstName $var_first.Text -LastName $var_last.Text -SamAccountName $loginid
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
    Send-MailMessage -To "$loginid@helios.net" -From "Administrator@helios.net" -Subject "Change your password" -body "Change it now." -smtpserver "mail.helios.net"
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
    $var_status.Text = "Done!"
})

$Null = $window.ShowDialog()
