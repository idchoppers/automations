<#
    Kyle Smith 6/28/2022

    Resets a password given an exchange email

    Usage: .\Set-ExchangePassword.ps1 <email>
#>

Param ( [Parameter(Mandatory=$True,Position=1)]$email )

$password = ""

# Connect
$msolCred = Get-Credential
Connect-MsolService –Credential $msolCred

# Reset Password
Set-MsolUserPassword -UserPrincipalName $email -NewPassword $password -ForceChangePassword $True

# Disconnect
Remove-PSSession $session