$ErrorActionPreference = 'Continue'
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$outdir = Join-Path $PSScriptRoot '..\agentcore_repro\out'
foreach ($op in @('list-gateways', 'list-policy-engines')) {
    $log = (Join-Path $outdir ('_clean_' + $op + '.log'))
    if (Test-Path $log) { Remove-Item $log -Force }
    & $aws bedrock-agentcore-control $op --region us-east-1 --output json *> $log
    Write-Host ('op=' + $op + '  EXIT=' + $LASTEXITCODE + '  size=' + (Get-Item $log).Length)
}