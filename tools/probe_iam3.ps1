$ErrorActionPreference = 'Continue'
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$probeRole = 'rot-ac-probe-' + [guid]::NewGuid().ToString('N').Substring(0,8)

Write-Host '=== 1) iam list-roles (read) ==='
$r = & $aws iam list-roles 2>&1 | Out-String
Write-Host ('EXIT=' + $LASTEXITCODE)
if ($r -match 'AccessDenied') { Write-Host 'CLASS=DENIED' } elseif ($r -match 'roleName') { Write-Host 'CLASS=OK' } else { Write-Host 'CLASS=OTHER'; Write-Host $r }

Write-Host '=== 2) iam create-role (probe) ==='
$r = & $aws iam create-role --role-name $probeRole `
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' 2>&1 | Out-String
Write-Host ('EXIT=' + $LASTEXITCODE)
$created = ($LASTEXITCODE -eq 0)
if (-not $created) { Write-Host $r }

Write-Host '=== 3) iam put-role-policy (probe) ==='
if ($created) {
  $r = & $aws iam put-role-policy --role-name $probeRole --policy-name probe `
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"lambda:InvokeFunction","Resource":"*"}]}' 2>&1 | Out-String
  Write-Host ('EXIT=' + $LASTEXITCODE)
  if ($LASTEXITCODE -ne 0) { Write-Host $r }
}

Write-Host '=== 4) cleanup (delete-role-policy + delete-role) ==='
if ($created) {
  & $aws iam delete-role-policy --role-name $probeRole --policy-name probe 2>&1 | Out-String | Write-Host
  $delPol = $LASTEXITCODE
  & $aws iam delete-role --role-name $probeRole 2>&1 | Out-String | Write-Host
  $delRole = $LASTEXITCODE
  Write-Host ("delete-role-policy EXIT=" + $delPol + "   delete-role EXIT=" + $delRole)
} else {
  Write-Host 'skipped (create-role failed)'
}