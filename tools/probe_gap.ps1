$ErrorActionPreference = 'Continue'
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$outdir = 'C:\Users\jeren\Documents\KAMANU\ROTN\agentcore_repro\out'

function Run($name, $cli) {
    $log = Join-Path $outdir ('_gap_' + $name + '.log')
    if (Test-Path $log) { Remove-Item $log -Force }
    & $aws @cli *> $log
    $txt = Get-Content $log -Raw
    if ($txt -match 'AccessDenied')            { $cls = 'DENIED' }
    elseif ($txt -match 'Could not connect')   { $cls = 'CONN_FAIL' }
    elseif ($txt -match '"Account"')           { $cls = 'OK' }
    elseif ($txt -match 'Functions"')          { $cls = 'OK' }
    elseif ($txt -match 'logGroups"')          { $cls = 'OK' }
    elseif ($txt -match 'Namespace' -or $txt -match 'Metrics"') { $cls = 'OK' }
    elseif ($txt -match 'policyEngines"')      { $cls = 'OK' }
    elseif ($txt -match 'items"')              { $cls = 'OK' }
    else                                       { $cls = 'OTHER' }
    Write-Host ('name=' + $name + '  EXIT=' + $LASTEXITCODE + '  class=' + $cls)
}

Run 'sts'         @('sts','get-caller-identity','--output','json')
Run 'lambda'      @('lambda','list-functions','--output','json')
Run 'logs'        @('logs','describe-log-groups','--log-group-name-prefix','/aws/lambda','--output','json')
Run 'cw'          @('cloudwatch','list-metrics','--namespace','AWS/Lambda','--output','json')
Run 'ac-pe'       @('bedrock-agentcore-control','list-policy-engines','--output','json')
Run 'ac-gw'       @('bedrock-agentcore-control','list-gateways','--output','json')