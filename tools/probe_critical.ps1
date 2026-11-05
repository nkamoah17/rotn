$ErrorActionPreference = 'Continue'
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$probeRole = 'rot-ac-probe-' + [guid]::NewGuid().ToString('N').Substring(0,8)

Write-Host '=== 1) iam create-role (the exact 10_setup blocker) ==='
$r = & $aws iam create-role --role-name $probeRole `
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' 2>&1 | Out-String
Write-Host ('EXIT=' + $LASTEXITCODE)
Write-Host $r
$created = ($LASTEXITCODE -eq 0)

Write-Host '=== 2) lambda list-functions ==='
$r = & $aws lambda list-functions 2>&1 | Out-String
Write-Host ('EXIT=' + $LASTEXITCODE)
if ($r -match 'AccessDenied') { Write-Host 'CLASS=DENIED' } elseif ($r -match 'FunctionName') { Write-Host 'CLASS=OK' } else { Write-Host 'CLASS=OTHER'; Write-Host $r }

Write-Host '=== 3) cleanup probe role (if created) ==='
if ($created) {
  & $aws iam delete-role --role-name $probeRole 2>&1 | Out-String | Write-Host
  Write-Host ('cleanup EXIT=' + $LASTEXITCODE)
} else {
  Write-Host 'nothing to clean up (create-role did not succeed)'
}