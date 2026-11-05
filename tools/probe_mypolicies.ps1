$ErrorActionPreference = 'Continue'
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$user = 'nkamoah17'

Write-Host '=== attached managed policies ==='
& $aws iam list-attached-user-policies --user-name $user --output json 2>&1 | Out-String | Write-Host

Write-Host '=== inline policies ==='
& $aws iam list-user-policies --user-name $user --output json 2>&1 | Out-String | Write-Host