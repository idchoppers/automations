#Requires -RunAsAdministrator 
<#
    Kyle Smith - June 2nd, 2022

    This script makes a rule to whitelist a number of either addresses or domains in a CSV file.
    It can be run on an Exchange Server.

    To use:
    1. Must have Admin privs
    2. You must install the Azure AD module.
        Install-Module MSOnline

    Changelog:
    June 2nd
        v1
        - Made basic logic
        v2
        - Switched from args[] to Param()
        - Added error handling
        - Added debug messages
    June 3rd 
        - Added color to debug messages for easier reading
        - Changed error handling from printing $_ to printing a cleaner way through $($PSItem.ToString())
        - Added logic to test if the rule passed in param 1 exists, then either makes a new one or appends to existing
    June 6th
        - Changed logic for the whitelist function
        - Added requires statement for Admin privs
#>

# Gather input from user
Param 
(
    [Parameter(Mandatory=$True,Position=1)]
    [string]$RuleName,

    [Parameter(Mandatory=$True,Position=2)]
    [string]$CsvPath
)

function Connect-Office365 
{
    Set-ExecutionPolicy RemoteSigned
    $LiveCred = Get-Credential
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.outlook.com/powershell/ -Credential $LiveCred -Authentication Basic -AllowRedirection
    Import-Module (Import-PSSession $Session -Allowclobber) -Global
    Connect-MsolService -Credential $LiveCred
}

function Disconnect-Office365 
{
    Write-Host "Disconnecting from Office 365..." -ForegroundColor Cyan
    Get-PSSession | Where-Object {$_.computername -like "*.outlook.com"} | Remove-PSSession
    Write-Host "Disconnected from Office 365!" -ForegroundColor Green
}

# Connect to server
Write-Host "Connecting to Office 365..." -ForegroundColor Cyan
try 
{
    Connect-Office365
}
catch
{
    Write-Host "An error occured while attempting to connect: " -ForegroundColor Red
    Write-Host "$($PSItem.ToString())" -ForegroundColor Red
    exit
}
Write-Host "Connection successful!" -ForegroundColor Green

# Whitelist domains/addresses
if (Get-TransportRule $RuleName -ea SilentlyContinue)
{
    try
    {
        Write-Host "Updating rule" $RuleName "..." -ForegroundColor Cyan
        foreach ($content in (Get-Content $CsvPath)){$temp=(Get-TransportRule $RuleName).FromAddressContainsWords; $temp+=$content; Set-TransportRule $RuleName -FromAddressContainsWords $temp}
    }
    catch
    {
        Write-Host "An error occured while attempting to create whitelist: " -ForegroundColor Red
        Write-Host "$($PSItem.ToString())" -ForegroundColor Red
        Disconnect-Office365
        exit
    }
}
else
{
    try 
    {
        Write-Host "Creating rule" $RuleName "and applying whitelist..." -ForegroundColor Cyan
        New-TransportRule $RuleName -SenderDomains $(foreach ($content in (Get-Content $CsvPath)){$temp=(Get-TransportRule $RuleName).FromAddressContainsWords; $temp+=$content; Set-TransportRule $RuleName -FromAddressContainsWords $temp}) -SetSCL "-1"
    }
    catch
    {
        Write-Host "An error occured while attempting to create whitelist: " -ForegroundColor Red
        Write-Host "$($PSItem.ToString())" -ForegroundColor Red
        Disconnect-Office365
        exit
    }
}

Write-Host "Created whitelist successfully!" -ForegroundColor Green

Disconnect-Office365
exit