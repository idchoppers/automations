<#
    To use:
    1. Run in elevated prompt

    2. You must install the Azure AD module.
        Install-Module MSOnline
#>

# Connects to O365 Powershell service using the credentials provided by user
function Connect-Office365 
{
    Set-ExecutionPolicy RemoteSigned
    $LiveCred = Get-Credential
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.outlook.com/powershell/ -Credential $LiveCred -Authentication Basic -AllowRedirection
    Import-Module (Import-PSSession $Session -Allowclobber) -Global
    Connect-MsolService -Credential $LiveCred
}

# Disconnect from O365 server
function Disconnect-Office365 
{
    Get-PSSession | Where-Object {$_.computername -like "*.outlook.com"} | Remove-PSSession
}

# Checks if the user provided a file
switch ( Test-Path $args[0] )
{
    True
    {
        $CsvPath = $args[0]
    }
    Default
    {
        Write-Host 'Usage .\whitelist.ps1 [PATH-TO-CSV]'
        exit
    }
}

Connect-Office365

# Ask user to choose either Addresses or Domains list, then runs respective command
Write-Host '1. Addresses'
Write-Host '2. Domains'
$Choice = Read-Host -Prompt '> '

switch ( $Choice )
{
    1 
    {
        Write-Host 'Adresses selected, applying list...'
        foreach ($content in (Get-Content $CsvPath)){$temp=(Get-TransportRule "Whitelist sender address matches").FromAddressContainsWords; $temp+=$content; Set-TransportRule "Whitelist sender address matches" -FromAddressContainsWords $temp}
        break
    }
    2 
    {
        Write-Host 'Domains selected, applying list...'
        foreach ($content in (Get-Content $CsvPath)){$temp=(Get-TransportRule "Whitelist 2").FromAddressContainsWords; $temp+=$content; Set-TransportRule "Whitelist 2" -FromAddressContainsWords $temp}
        break
    }
    Default 
    { 
        Write-Host 'Input niether 1 or 2, exiting.'
        Disconnect-Office365
        exit 
    }
}

Disconnect-Office365
exit