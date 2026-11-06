$ErrorActionPreference = 'Continue'
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$outdir = Join-Path $PSScriptRoot '..\agentcore_repro\out'

function Run($name, $cli) {
    $log = Join-Path $outdir ('_iamprobe_' + $name + '.log')
    if (Test-Path $log) { Remove-Item $log -Force }
    & $aws @cli *> $log
    $cls = 'OK'
    $txt = Get-Content $log -Raw
    if ($txt -match 'AccessDenied') { $cls = 'ACCESS_DENIED' }
    elseif ($txt -match 'NoSuchEntity') { $cls = 'NO_SUCH_ENTITY' }
    elseif ($txt -match 'Could not connect') { $cls = 'CONN_FAIL' }
    elseif ($txt -match 'MalformedPolicyDocument') { $cls = 'MALFORMED' }
    elseif ($txt -match 'EntityAlreadyExists') { $cls = 'ALREADY_EXISTS' }
    $sz = (Get-Item $log).Length
    Write-Host ('name=' + $name + '  EXIT=' + $LASTEXITCODE + '  class=' + $cls + '  size=' + $sz)
    Write-Host ('   first line: ' + (($txt -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 1) -replace '^\s+',''))
}

Run 'get-role'        @('iam','get-role','--role-name','rot-ac-gateway-role','--output','json')
Run 'list-roles'      @('iam','list-roles','--output','json')
Run 'create-role'     @('iam','create-role','--role-name','rot-ac-iamprobe-tmp','--assume-role-policy-document','{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}')
Run 'put-role-policy' @('iam','put-role-policy','--role-name','rot-ac-iamprobe-tmp','--policy-name','probe','--policy-document','{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"lambda:InvokeFunction","Resource":"*"}]}')
Run 'attach-role-pol' @('iam','attach-role-policy','--role-name','rot-ac-iamprobe-tmp','--policy-arn','arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole')

Write-Host '--- cleanup probe role (if created) ---'
& $aws iam delete-role-policy --role-name 'rot-ac-iamprobe-tmp' --policy-name 'probe' 2>&1 | Out-String | Write-Host
& $aws iam detach-role-policy --role-name 'rot-ac-iamprobe-tmp' --policy-arn 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole' 2>&1 | Out-String | Write-Host
& $aws iam delete-role --role-name 'rot-ac-iamprobe-tmp' 2>&1 | Out-String | Write-Host
Write-Host ('cleanup EXIT=' + $LASTEXITCODE)