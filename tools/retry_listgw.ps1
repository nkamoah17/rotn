$ErrorActionPreference = 'Continue'
$env:AWS_CLI_DEBUG = '1'
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$log = 'C:\Users\jeren\Documents\KAMANU\ROTN\agentcore_repro\out\_listgw_debug.log'
if (Test-Path $log) { Remove-Item $log -Force }
& $aws bedrock-agentcore-control list-gateways --region us-east-1 *> $log
Write-Host ('EXIT=' + $LASTEXITCODE)
Write-Host ('log=' + $log)
Write-Host ('size=' + (Get-Item $log).Length + ' bytes')