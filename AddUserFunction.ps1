Import-Module psexcel
#import the module for reading from xlsx
$file = Import-XLSX C:\Users\Administrator\Documents\Users.xlsx -header firstName, lastName
#make a file variable to read in the xlsx file and define the headers that I want to user so they can 
#be referenced later.

#$file[0]
#global variables such as the initial password before the change and the counter for group membership
$password = "Password01"
$maxOUsize = 50
$created = 0;

#function to create user directories and assign them permissions

function Home-Dir {

    #gets the ad user that is being iterated over and checks to see if it is null before making a folder for it
    $User = Get-ADUser -Identity $uNameLower
    if ($User -ne $Null) {

        #set users home drive and mapping as well as create the directory 
        Set-ADuser $User -HomeDrive $drive -HomeDirectory $fullPath -ea Stop
        $homeshare = New-Item -path $fullPath -ItemType Directory -force -ea Stop

        #create a acl object to add rules that need to be assigned to the new folder
        $acl = Get-Acl $homeshare

        #remove any permissions that may have been inherited from parent folders
        #we are assigning all the required permissions manually
        $acl.SetAccessRuleProtection($true, $false)

        #setup variables for different access rules for both the new user and the domain admins
        #the inheretance ones are commented because i wanted their values to be null but still use them in the
        #new rule object
        $FileSystemRights = [System.Security.AccessControl.FileSystemRights]"Modify"
        $AdminSystemRights = [System.Security.AccessControl.FileSystemRights]"FullControl"
        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
        #$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
        #$PropagationFlags = [System.Security.AccessControl.PropagationFlags]"None"
                


        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($User.SID, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)
                
        #creating two new rules, one for the new user and one for the admin and assigning them to the acl 
        #that was created earlier

        $acl.AddAccessRule($AccessRule)

        $AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Admins", $AdminSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)
        $acl.AddAccessRule($AdminRule)

        Set-Acl -Path $homeshare -AclObject $acl -ea Stop

        #output a message with the path to the newly created folder
        #Write-Host ("HomeDir created at {0}" -f $fullPath)

    }
}

#function to create the users. It takes one peramater which is the group that it will be added to.
function Create-User {
    param([int]$group)
    #all of the peramaters for adding the users with all of the required information. Name, accountname, password etc
    New-ADUser `
        -Name $fullName `
        -GivenName $line.firstName `
        -SurName $line.lastName `
        -SamAccountName $uNameLower `
        -UserPrincipalName $principal `
        -AccountPassword $(ConvertTo-SecureString $password -AsPlainText -Force) `
        -ChangePasswordAtLogon $True `
        -Enabled $True `
        -Path "OU=Group $group,DC=powerdc,DC=com"
    #-HomeDrive H: `
    #-HomeDirectory $homeDirectory
    Write-Host User $fullName Was Added to Group $group
    #run the create homdir function on the user that is being created
    Home-Dir
}

#forloop to iterate over each line in the file and use its info to create a user.
foreach ($line in $file) {

    #creating variables for use in the loop. Modifying the strings to get username format and define the
    #home directory
    $uName = $line.firstName[0] + $line.lastName
    $principal = $uName.Tolower() + "@powerdc.com"
    $fullName = $line.firstName + " " + $line.lastName
    $uNameLower = $uName.ToLower()
    #$homeDirectory = '\\PowerDC\ShareV3$\'+$uNameLower;

        
    $fullPath = "\\powerdc\ShareV3$\users\{0}" -f $uNameLower
    $drive = "H:\"

    $lastName = Out-String -InputObject $line.lastName

    #if statement to check if the lastname of the user is blank and if so return a message
    if ($lastName -eq "") {
        Write-Host Warning User Does Not Have A Last Name -ForegroundColor Green
        continue

        #various if statement to determine what the count of created users is so that it can decide
        #which group to put the user in.
    }
    elseif ($created -le 50) {

        #run the create user function that will make the user and map its drive
        Create-User -group 1
        $created++
        #increment the counter so that the if statements can determing which group to user for next user.

    }
    elseif ($created -le 100 -and $created -gt 50) {

        Create-User -group 2
        $created++

    }
    elseif ($created -le 150 -and $created -gt 100) {
            
        Create-User -group 3
        $created++

    }
    elseif ($created -le 200 -and $created -gt 150) {
            
        Create-User -group 4
        $created++

    }
    elseif ($created -le 250 -and $created -gt 200) {

        Create-User -group 5
        $created++

    }
    elseif ($created -le 300 -and $created -gt 250) {

        Create-User -group 6
        $created++

    }

}