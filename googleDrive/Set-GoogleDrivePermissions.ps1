<#
    Kyle Smith 6/28/2022

    This script will APPEND users and permissions to the target object.
    
    The script reads from a CSV file with two columns (User,Permission) and assigns that user their respective permission for a file or folder.
    
    The target object is the ID found using gdrive.exe list or found in the URL at drive.google.com
    Ex: https://drive.google.com/drive/folders/l0ts0fch4ract3rs0000
                                               ^ ID

    Usage: .\Set-GoogleDrivePermissions.ps1 <CSVFilePath> <ID>

    Dependencies:
     - gdrive.exe in working directory
     - gdrive should have permissions to work with the target account
#>

Param (
    [Parameter(Mandatory=$True,Position=1)]
    [string]$csv,
    [Parameter(Mandatory=$True,Position=2)]
    [string]$id
)

Import-Csv $csv | ForEach-Object {
    #Write-Host ".\gdrive.exe share $($id) --type user --email $($_.User) --role $($_.Permission)"
    Invoke-Expression -Command ".\gdrive.exe share $($id) --type user --email $($_.User) --role $($_.Permission)"
}
