# Launches AWS CLI v2 (winget) and AgentCore CLI (npm) installs as detached
# background jobs. Poll with:  tools\poll_installs.ps1
$ErrorActionPreference = 'Stop'
$logdir = Join-Path $PSScriptRoot 'install_logs'
New-Item -ItemType Directory -Force -Path $logdir | Out-Null

$p1 = Start-Process powershell.exe -WindowStyle Hidden -PassThru `
    -ArgumentList '-NoProfile','-Command',
    "winget install -e --id Amazon.AWSCLI --accept-source-agreements --accept-package-agreements --silent | Out-File '$(Join-Path $logdir 'awscli.log')' -Encoding utf8"
$p2 = Start-Process powershell.exe -WindowStyle Hidden -PassThru `
    -ArgumentList '-NoProfile','-Command',
    "npm install -g @aws/agentcore 2>&1 | Out-File '$(Join-Path $logdir 'agentcore.log')' -Encoding utf8"
Write-Host ('launched winget job pid=' + $p1.Id + '  npm job pid=' + $p2.Id)
