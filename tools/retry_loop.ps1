$ErrorActionPreference = 'Continue'
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$counts = @{}
for ($i = 1; $i -le 5; $i++) {
    $out = (& $aws bedrock-agentcore-control list-gateways --region us-east-1 2>&1 | Out-String)
    if ($out -match 'AccessDenied')        { $cls = 'AccessDenied' }
    elseif ($out -match 'Could not connect') { $cls = 'CouldNotConnect' }
    elseif ($out -match '"items"')          { $cls = 'OK' }
    else { $cls = 'Other' }
    $counts[$cls] = [int]$counts[$cls] + 1
    Write-Host ("attempt " + $i + " : " + $cls)
}
Write-Host '--- summary ---'
$counts.GetEnumerator() | ForEach-Object { Write-Host ($_.Key + ' = ' + $_.Value) }