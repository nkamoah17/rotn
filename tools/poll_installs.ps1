# Polls the two background install jobs; prints status + tails of each log.
$ErrorActionPreference = 'Continue'
$logdir = Join-Path $PSScriptRoot 'install_logs'
$busy = Get-Process | Where-Object { $_.ProcessName -match 'winget|npm|node' }
Write-Host ('busy processes: ' + @($busy | ForEach-Object { $_.ProcessName + '(' + $_.Id + ')' }) -join ', ')

foreach ($name in @('awscli.log', 'agentcore.log')) {
    $p = Join-Path $logdir $name
    if (Test-Path $p) {
        $tail = Get-Content $p -Tail 6 -ErrorAction SilentlyContinue
        Write-Host ('--- ' + $name + ' ---')
        $tail | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host ('--- ' + $name + ' (not yet) ---')
    }
}

$aws = Get-Command aws -ErrorAction SilentlyContinue
if ($aws) { Write-Host ('AWS CLI: ' + $aws.Source); & $aws.Source --version }
$ac = Get-Command agentcore -ErrorAction SilentlyContinue
if ($ac) { Write-Host ('AgentCore CLI: ' + $ac.Source) }
