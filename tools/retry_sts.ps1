$ErrorActionPreference = 'Continue'
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'

Write-Host '=== DNS: sts.us-east-1.amazonaws.com ==='
try { Resolve-DnsName 'sts.us-east-1.amazonaws.com' -ErrorAction Stop | Where-Object { $_.RecordType -eq 'A' } | Select-Object Name,IPAddress | Format-Table -AutoSize | Out-String | Write-Host } catch { Write-Host ('DNS FAIL: ' + $_.Exception.Message) }

Write-Host '=== DNS: bedrock-agentcore-control.us-east-1.amazonaws.com ==='
try { Resolve-DnsName 'bedrock-agentcore-control.us-east-1.amazonaws.com' -ErrorAction Stop | Where-Object { $_.RecordType -eq 'A' } | Select-Object Name,IPAddress | Format-Table -AutoSize | Out-String | Write-Host } catch { Write-Host ('DNS FAIL: ' + $_.Exception.Message) }

Write-Host '=== Retry loop: sts get-caller-identity (8 attempts) ==='
$ok = 0; $fail = 0
for ($i = 1; $i -le 8; $i++) {
    $t0 = Get-Date
    $out = (& $aws sts get-caller-identity --region us-east-1 2>&1 | Out-String)
    $ms = ((Get-Date) - $t0).TotalMilliseconds
    if ($out -match '"Account"') { $cls = 'OK'; $ok++ }
    elseif ($out -match 'Could not connect') { $cls = 'CONN_FAIL'; $fail++ }
    elseif ($out -match 'AccessDenied') { $cls = 'ACCESS_DENIED'; $fail++ }
    else { $cls = 'Other'; $fail++ }
    Write-Host ("  attempt " + $i + " : " + $cls + "  (" + [int]$ms + " ms)")
    Start-Sleep -Milliseconds 700
}
Write-Host ('SUMMARY: ok=' + $ok + '  fail=' + $fail)