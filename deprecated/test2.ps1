$file = Import-CSV C:\Users\Administrator\Documents\Users.csv -header firstName, lastName

#$file[0]
$password = "Password01"
$maxOUsize = 50
$created = 0;

foreach($line in $file) {

        $uName = $line.firstName[0]+$line.lastName
        $principal = $uName.Tolower()+"@powerdc.com"
        $fullName = $line.firstName + " " + $line.lastName
        $uNameLower = $uName.ToLower()
        $homeDirectory = '\\PowerDC\ShareV3$\'+$uNameLower;

        
        $fullPath = "\\powerdc\ShareV3$\users\{0}" -f $uNameLower
        $drive = "H:\"

        if($line.lastName -eq "") {
            Write-Host Warning User Does Not Have A Last Name
            continue
        }elseif($created -le 50) {
            
            New-ADUser `
            -Name $fullName `
            -GivenName $line.firstName `
            -SurName $line.lastName `
            -SamAccountName $uNameLower `
            -UserPrincipalName $principal `
            -AccountPassword $(ConvertTo-SecureString $password -AsPlainText -Force) `
            -ChangePasswordAtLogon $True `
            -Enabled $True `
            -Path "OU=Group 1,DC=powerdc,DC=com"
            #-HomeDrive H: `
            #-HomeDirectory $homeDirectory
            Write-Host User $fullName Was Added to Group 1
            $created++

            $User = Get-ADUser -Identity $uNameLower
            if($User -ne $Null) {
                Set-ADuser $User -HomeDrive $drive -HomeDirectory $fullPath -ea Stop
                $homeshare = New-Item -path $fullPath -ItemType Directory -force -ea Stop

                $acl = Get-Acl $homeshare

                $acl.SetAccessRuleProtection($true,$false)


                $FileSystemRights = [System.Security.AccessControl.FileSystemRights]"Modify"
                $AdminSystemRights = [System.Security.AccessControl.FileSystemRights]"FullControl"
                $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                #$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
                #$PropagationFlags = [System.Security.AccessControl.PropagationFlags]"None"
                


                $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($User.SID, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)
                

                $acl.AddAccessRule($AccessRule)
                $AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Admins",$AdminSystemRights,$InheritanceFlags,$PropagationFlags,$AccessControlType)
                $acl.AddAccessRule($AdminRule)

                Set-Acl -Path $homeshare -AclObject $acl -ea Stop

                Write-Host ("HomeDir created at {0}" -f $fullPath)

            }
            #Set-ADUser -HomeDrive $drive -HomeDirectory $fullPath $share = New-Item -path $fullPath -ItemType Directory -force
        }elseif($created -le 100 -and $created -gt 50) {
            
            New-ADUser `
            -Name $fullName `
            -GivenName $line.firstName `
            -SurName $line.lastName `
            -SamAccountName $uName.ToLower() `
            -UserPrincipalName $principal `
            -AccountPassword $(ConvertTo-SecureString $password -AsPlainText -Force) `
            -ChangePasswordAtLogon $True `
            -Enabled $True `
            -Path "OU=Group 2,DC=powerdc,DC=com" `
            -HomeDrive H: `
            -HomeDirectory \\PowerDC\HomeDirShare$
            Write-Host User $fullName Was Added to Group 2
            $created++

            $User = Get-ADUser -Identity $uNameLower
            if($User -ne $Null) {
                Set-ADuser $User -HomeDrive $drive -HomeDirectory $fullPath -ea Stop
                $homeshare = New-Item -path $fullPath -ItemType Directory -force -ea Stop

                $acl = Get-Acl $homeshare

                $acl.SetAccessRuleProtection($true,$false)


                $FileSystemRights = [System.Security.AccessControl.FileSystemRights]"Modify"
                $AdminSystemRights = [System.Security.AccessControl.FileSystemRights]"FullControl"
                $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                #$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
                #$PropagationFlags = [System.Security.AccessControl.PropagationFlags]"InheritOnly"
                


                $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($User.SID, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)
                

                $acl.AddAccessRule($AccessRule)
                $AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Admins",$AdminSystemRights,$InheritanceFlags,$PropagationFlags,$AccessControlType)
                $acl.AddAccessRule($AdminRule)

                Set-Acl -Path $homeshare -AclObject $acl -ea Stop

                Write-Host ("HomeDir created at {0}" -f $fullPath)

                }

        }elseif($created -le 150 -and $created -gt 100) {
            
            New-ADUser `
            -Name $fullName `
            -GivenName $line.firstName `
            -SurName $line.lastName `
            -SamAccountName $uName.ToLower() `
            -UserPrincipalName $principal `
            -AccountPassword $(ConvertTo-SecureString $password -AsPlainText -Force) `
            -ChangePasswordAtLogon $True `
            -Enabled $True `
            -Path "OU=Group 3,DC=powerdc,DC=com" `
            -HomeDrive H: `
            -HomeDirectory \\PowerDC\HomeDirShare$
            Write-Host User $fullName Was Added to Group 3
            $created++

            $User = Get-ADUser -Identity $uNameLower
            if($User -ne $Null) {
                Set-ADuser $User -HomeDrive $drive -HomeDirectory $fullPath -ea Stop
                $homeshare = New-Item -path $fullPath -ItemType Directory -force -ea Stop

                $acl = Get-Acl $homeshare

                $acl.SetAccessRuleProtection($true,$false)


                $FileSystemRights = [System.Security.AccessControl.FileSystemRights]"Modify"
                $AdminSystemRights = [System.Security.AccessControl.FileSystemRights]"FullControl"
                $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                #$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
                #$PropagationFlags = [System.Security.AccessControl.PropagationFlags]"InheritOnly"
                


                $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($User.SID, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)
                

                $acl.AddAccessRule($AccessRule)
                $AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Admins",$AdminSystemRights,$InheritanceFlags,$PropagationFlags,$AccessControlType)
                $acl.AddAccessRule($AdminRule)

                Set-Acl -Path $homeshare -AclObject $acl -ea Stop

                Write-Host ("HomeDir created at {0}" -f $fullPath)

                }

        }elseif($created -le 200 -and $created -gt 150) {
            
            New-ADUser `
            -Name $fullName `
            -GivenName $line.firstName `
            -SurName $line.lastName `
            -SamAccountName $uName.ToLower() `
            -UserPrincipalName $principal `
            -AccountPassword $(ConvertTo-SecureString $password -AsPlainText -Force) `
            -ChangePasswordAtLogon $True `
            -Enabled $True `
            -Path "OU=Group 4,DC=powerdc,DC=com" `
            -HomeDrive H: `
            -HomeDirectory \\PowerDC\HomeDirShare$
            Write-Host User $fullName Was Added to Group 4
            $created++

            $User = Get-ADUser -Identity $uNameLower
            if($User -ne $Null) {
                Set-ADuser $User -HomeDrive $drive -HomeDirectory $fullPath -ea Stop
                $homeshare = New-Item -path $fullPath -ItemType Directory -force -ea Stop

                $acl = Get-Acl $homeshare

                $acl.SetAccessRuleProtection($true,$false)


                $FileSystemRights = [System.Security.AccessControl.FileSystemRights]"Modify"
                $AdminSystemRights = [System.Security.AccessControl.FileSystemRights]"FullControl"
                $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                #$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
                #$PropagationFlags = [System.Security.AccessControl.PropagationFlags]"InheritOnly"
                


                $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($User.SID, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)
                

                $acl.AddAccessRule($AccessRule)
                $AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Admins",$AdminSystemRights,$InheritanceFlags,$PropagationFlags,$AccessControlType)
                $acl.AddAccessRule($AdminRule)

                Set-Acl -Path $homeshare -AclObject $acl -ea Stop

                Write-Host ("HomeDir created at {0}" -f $fullPath)

                }

        }elseif($created -le 250 -and $created -gt 200) {
            
            New-ADUser `
            -Name $fullName `
            -GivenName $line.firstName `
            -SurName $line.lastName `
            -SamAccountName $uName.ToLower() `
            -UserPrincipalName $principal `
            -AccountPassword $(ConvertTo-SecureString $password -AsPlainText -Force) `
            -ChangePasswordAtLogon $True `
            -Enabled $True `
            -Path "OU=Group 5,DC=powerdc,DC=com" `
            -HomeDrive H: `
            -HomeDirectory \\PowerDC\HomeDirShare$
            Write-Host User $fullName Was Added to Group 5
            $created++

            $User = Get-ADUser -Identity $uNameLower
            if($User -ne $Null) {
                Set-ADuser $User -HomeDrive $drive -HomeDirectory $fullPath -ea Stop
                $homeshare = New-Item -path $fullPath -ItemType Directory -force -ea Stop

                $acl = Get-Acl $homeshare

                $acl.SetAccessRuleProtection($true,$false)


                $FileSystemRights = [System.Security.AccessControl.FileSystemRights]"Modify"
                $AdminSystemRights = [System.Security.AccessControl.FileSystemRights]"FullControl"
                $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                #$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
                #$PropagationFlags = [System.Security.AccessControl.PropagationFlags]"InheritOnly"
                


                $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($User.SID, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)
                

                $acl.AddAccessRule($AccessRule)
                $AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Admins",$AdminSystemRights,$InheritanceFlags,$PropagationFlags,$AccessControlType)
                $acl.AddAccessRule($AdminRule)

                Set-Acl -Path $homeshare -AclObject $acl -ea Stop

                Write-Host ("HomeDir created at {0}" -f $fullPath)

                }

        }elseif($created -le 300 -and $created -gt 250) {
            
            New-ADUser `
            -Name $fullName `
            -GivenName $line.firstName `
            -SurName $line.lastName `
            -SamAccountName $uName.ToLower() `
            -UserPrincipalName $principal `
            -AccountPassword $(ConvertTo-SecureString $password -AsPlainText -Force) `
            -ChangePasswordAtLogon $True `
            -Enabled $True `
            -Path "OU=Group 6,DC=powerdc,DC=com" `
            -HomeDrive H: `
            -HomeDirectory \\PowerDC\HomeDirShare$
            Write-Host User $fullName Was Added to Group 6
            $created++

            $User = Get-ADUser -Identity $uNameLower
            if($User -ne $Null) {
                Set-ADuser $User -HomeDrive $drive -HomeDirectory $fullPath -ea Stop
                $homeshare = New-Item -path $fullPath -ItemType Directory -force -ea Stop

                $acl = Get-Acl $homeshare

                $acl.SetAccessRuleProtection($true,$false)


                $FileSystemRights = [System.Security.AccessControl.FileSystemRights]"Modify"
                $AdminSystemRights = [System.Security.AccessControl.FileSystemRights]"FullControl"
                $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                #$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
                #$PropagationFlags = [System.Security.AccessControl.PropagationFlags]"InheritOnly"
                


                $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($User.SID, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)
                

                $acl.AddAccessRule($AccessRule)
                $AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Admins",$AdminSystemRights,$InheritanceFlags,$PropagationFlags,$AccessControlType)
                $acl.AddAccessRule($AdminRule)

                Set-Acl -Path $homeshare -AclObject $acl -ea Stop

                Write-Host ("HomeDir created at {0}" -f $fullPath)

                }

        }
}