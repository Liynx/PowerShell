#Get-Aduser -Filter 'enabled -eq $true' -properties Name, homedirectory -SearchBase 'OU=Group 1,DC=powerdc,DC=com' | `
#ForEach-Object {
#    Remove-Item -Path $_.homedirectory -Force -Recurse
#}

#function to find and delete all users in a group and their home directories and then delete them
function Del_Folders {
    param([int]$group)
    Get-Aduser -Filter 'enabled -eq $true' -properties Name, homedirectory -SearchBase "OU=Group $group,DC=powerdc,DC=com" | `
        ForEach-Object {
        Remove-Item -Path $_.homedirectory -Force -Recurse
    }
}

Del_Folders -group 1
Del_Folders -group 2
Del_Folders -group 3
Del_Folders -group 4
Del_Folders -group 5
Del_Folders -group 6

#same function but to delete the OUs after all of the home directories have been deleted. 
Get-ADOrganizationalUnit -Filter 'Name -like "Group*"' | Set-ADObject -ProtectedFromAccidentalDeletion $false `
    -PassThru | Remove-ADOrganizationalUnit -Confirm:$false -Recursive