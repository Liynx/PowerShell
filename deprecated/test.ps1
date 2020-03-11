$path = "OU=Group 1,DC=powerdc,DC=com";

Get-ADUser -LDAPFilter '(samAccountName="chottle")' -path $path;
#get-aduser -Identity chottle -SearchBase $path -properties name