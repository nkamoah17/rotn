$ErrorActionPreference = 'Continue'
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$u = 'nkamoah17'
$outdir = 'C:\Users\jeren\Documents\KAMANU\ROTN\agentcore_repro\out'

function Run($name, $args) {
    $log = Join-Path $outdir ('_iam_' + $name + '.log')
    if (Test-Path $log) { Remove-Item $log -Force }
    & $aws @args *> $log
    $sz = (Get-Item $log).Length
    Write-Host ('name=' + $name + '  EXIT=' + $LASTEXITCODE + '  size=' + $sz + '  log=' + $log)
}

Run 'get-user'            @('iam','get-user','--user-name',$u,'--output','json')
Run 'attached-user-pol'   @('iam','list-attached-user-policies','--user-name',$u,'--output','json')
Run 'inline-user-pol'     @('iam','list-user-policies','--user-name',$u,'--output','json')
Run 'list-managed'        @('iam','list-policies','--scope','Local','--output','json')
Run 'list-managed-aws'    @('iam','list-policies','--scope','AWS','--output','json')